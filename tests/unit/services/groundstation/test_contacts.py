"""Unit tests for Ground Station contact operations."""

from datetime import datetime

import pytest

from localstack.aws.api import RequestContext
from localstack.aws.api.groundstation import (
    ContactStatus,
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
def test_mission_profile(provider, context):
    """Create a test mission profile for contact operations."""
    # Create configs
    tracking_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
    tracking_resp = provider.create_config(
        context=context, name="test-tracking", config_data=tracking_data
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
        context=context, name="test-downlink", config_data=downlink_data
    )

    def_data = {
        "dataflowEndpointConfig": {
            "dataflowEndpointName": "test-endpoint",
            "dataflowEndpointRegion": "us-east-1",
        }
    }
    def_resp = provider.create_config(context=context, name="test-dataflow", config_data=def_data)

    # Create mission profile
    mp_resp = provider.create_mission_profile(
        context=context,
        name="test-mission",
        minimum_viable_contact_duration_seconds=60,
        contact_pre_pass_duration_seconds=120,
        contact_post_pass_duration_seconds=60,
        tracking_config_arn=tracking_resp["configArn"],
        dataflow_edges=[
            [tracking_resp["configArn"], downlink_resp["configArn"]],
            [downlink_resp["configArn"], def_resp["configArn"]],
        ],
    )

    mp_id = mp_resp["missionProfileId"]
    mp_arn = f"arn:aws:groundstation:us-east-1:000000000000:mission-profile/{mp_id}"

    return {"mission_profile_arn": mp_arn, "mission_profile_id": mp_id}


class TestReserveContact:
    """Tests for ReserveContact operation."""

    def test_reserve_basic_contact(self, provider, context, test_mission_profile):
        """Test reserving a basic contact."""
        start_time = datetime(2025, 12, 31, 12, 0, 0)
        end_time = datetime(2025, 12, 31, 13, 0, 0)

        response = provider.reserve_contact(
            context=context,
            mission_profile_arn=test_mission_profile["mission_profile_arn"],
            satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/11111111-1111-1111-1111-000000025544",
            start_time=start_time,
            end_time=end_time,
            ground_station="Ohio Ground Station",
        )

        assert "contactId" in response
        contact_id = response["contactId"]
        assert contact_id in groundstation_stores.contacts

        contact = groundstation_stores.contacts[contact_id]
        assert contact.contact_status == ContactStatus.SCHEDULED
        assert contact.start_time == start_time
        assert contact.end_time == end_time

    def test_reserve_contact_with_tags(self, provider, context, test_mission_profile):
        """Test reserving a contact with tags."""
        start_time = datetime(2025, 12, 31, 12, 0, 0)
        end_time = datetime(2025, 12, 31, 13, 0, 0)
        tags = {"Mission": "ISS", "Priority": "High"}

        response = provider.reserve_contact(
            context=context,
            mission_profile_arn=test_mission_profile["mission_profile_arn"],
            satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/11111111-1111-1111-1111-000000025544",
            start_time=start_time,
            end_time=end_time,
            ground_station="Ohio Ground Station",
            tags=tags,
        )

        contact_id = response["contactId"]
        contact = groundstation_stores.contacts[contact_id]
        assert contact.tags == tags

    def test_reserve_contact_invalid_times(self, provider, context, test_mission_profile):
        """Test that end time before start time is rejected."""
        start_time = datetime(2025, 12, 31, 13, 0, 0)
        end_time = datetime(2025, 12, 31, 12, 0, 0)  # Before start

        with pytest.raises(InvalidParameterException) as exc:
            provider.reserve_contact(
                context=context,
                mission_profile_arn=test_mission_profile["mission_profile_arn"],
                satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/11111111-1111-1111-1111-000000025544",
                start_time=start_time,
                end_time=end_time,
                ground_station="Ohio Ground Station",
            )

        assert "end time must be after start time" in str(exc.value).lower()

    def test_reserve_contact_nonexistent_mission_profile(self, provider, context):
        """Test that reserving with non-existent mission profile fails."""
        start_time = datetime(2025, 12, 31, 12, 0, 0)
        end_time = datetime(2025, 12, 31, 13, 0, 0)

        with pytest.raises(ResourceNotFoundException):
            provider.reserve_contact(
                context=context,
                mission_profile_arn="arn:aws:groundstation:us-east-1:000000000000:mission-profile/nonexistent",
                satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/11111111-1111-1111-1111-000000025544",
                start_time=start_time,
                end_time=end_time,
                ground_station="Ohio Ground Station",
            )

    def test_reserve_contact_nonexistent_satellite(self, provider, context, test_mission_profile):
        """Test that reserving with non-existent satellite fails."""
        start_time = datetime(2025, 12, 31, 12, 0, 0)
        end_time = datetime(2025, 12, 31, 13, 0, 0)

        with pytest.raises(ResourceNotFoundException):
            provider.reserve_contact(
                context=context,
                mission_profile_arn=test_mission_profile["mission_profile_arn"],
                satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/nonexistent-satellite-id-here-111111",
                start_time=start_time,
                end_time=end_time,
                ground_station="Ohio Ground Station",
            )


class TestDescribeContact:
    """Tests for DescribeContact operation."""

    def test_describe_existing_contact(self, provider, context, test_mission_profile):
        """Test describing an existing contact."""
        # Reserve a contact
        start_time = datetime(2025, 12, 31, 12, 0, 0)
        end_time = datetime(2025, 12, 31, 13, 0, 0)

        reserve_resp = provider.reserve_contact(
            context=context,
            mission_profile_arn=test_mission_profile["mission_profile_arn"],
            satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/11111111-1111-1111-1111-000000025544",
            start_time=start_time,
            end_time=end_time,
            ground_station="Ohio Ground Station",
        )
        contact_id = reserve_resp["contactId"]

        # Describe the contact
        response = provider.describe_contact(context=context, contact_id=contact_id)

        assert response["contactId"] == contact_id
        assert response["contactStatus"] == ContactStatus.SCHEDULED
        assert response["groundStation"] == "Ohio Ground Station"
        assert response["missionProfileArn"] == test_mission_profile["mission_profile_arn"]

    def test_describe_nonexistent_contact(self, provider, context):
        """Test describing a non-existent contact."""
        with pytest.raises(ResourceNotFoundException):
            provider.describe_contact(context=context, contact_id="nonexistent-contact-id")


class TestListContacts:
    """Tests for ListContacts operation."""

    def test_list_contacts_empty(self, provider, context):
        """Test listing contacts when none exist."""
        start_time = datetime(2025, 1, 1, 0, 0, 0)
        end_time = datetime(2025, 12, 31, 23, 59, 59)

        response = provider.list_contacts(
            context=context,
            start_time=start_time,
            end_time=end_time,
            status_list=[ContactStatus.SCHEDULED],
        )

        assert response["contactList"] == []

    def test_list_contacts_by_time_range(self, provider, context, test_mission_profile):
        """Test listing contacts filtered by time range."""
        # Create contacts at different times
        contact1_start = datetime(2026, 6, 1, 12, 0, 0)
        contact1_end = datetime(2026, 6, 1, 13, 0, 0)

        contact2_start = datetime(2026, 12, 1, 12, 0, 0)
        contact2_end = datetime(2026, 12, 1, 13, 0, 0)

        provider.reserve_contact(
            context=context,
            mission_profile_arn=test_mission_profile["mission_profile_arn"],
            satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/11111111-1111-1111-1111-000000025544",
            start_time=contact1_start,
            end_time=contact1_end,
            ground_station="Ohio Ground Station",
        )

        provider.reserve_contact(
            context=context,
            mission_profile_arn=test_mission_profile["mission_profile_arn"],
            satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/22222222-2222-2222-2222-000000043013",
            start_time=contact2_start,
            end_time=contact2_end,
            ground_station="Alaska Ground Station",
        )

        # List contacts in June 2026
        response = provider.list_contacts(
            context=context,
            start_time=datetime(2026, 6, 1, 0, 0, 0),
            end_time=datetime(2026, 6, 30, 23, 59, 59),
            status_list=[ContactStatus.SCHEDULED],
        )

        assert len(response["contactList"]) == 1
        assert response["contactList"][0]["groundStation"] == "Ohio Ground Station"

    def test_list_contacts_by_status(self, provider, context, test_mission_profile):
        """Test listing contacts filtered by status."""
        # Reserve a contact
        start_time = datetime(2026, 12, 31, 12, 0, 0)
        end_time = datetime(2026, 12, 31, 13, 0, 0)

        reserve_resp = provider.reserve_contact(
            context=context,
            mission_profile_arn=test_mission_profile["mission_profile_arn"],
            satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/11111111-1111-1111-1111-000000025544",
            start_time=start_time,
            end_time=end_time,
            ground_station="Ohio Ground Station",
        )
        contact_id = reserve_resp["contactId"]

        # Cancel it
        provider.cancel_contact(context=context, contact_id=contact_id)

        # List only SCHEDULED contacts (should be empty)
        response = provider.list_contacts(
            context=context,
            start_time=datetime(2026, 1, 1, 0, 0, 0),
            end_time=datetime(2027, 1, 1, 0, 0, 0),
            status_list=[ContactStatus.SCHEDULED],
        )
        assert len(response["contactList"]) == 0

        # List CANCELLED contacts (should find the cancelled one)
        response = provider.list_contacts(
            context=context,
            start_time=datetime(2026, 1, 1, 0, 0, 0),
            end_time=datetime(2027, 1, 1, 0, 0, 0),
            status_list=[ContactStatus.CANCELLED],
        )
        assert len(response["contactList"]) == 1
        assert response["contactList"][0]["contactStatus"] == ContactStatus.CANCELLED


class TestCancelContact:
    """Tests for CancelContact operation."""

    def test_cancel_scheduled_contact(self, provider, context, test_mission_profile):
        """Test canceling a scheduled contact."""
        # Reserve a contact
        start_time = datetime(2025, 12, 31, 12, 0, 0)
        end_time = datetime(2025, 12, 31, 13, 0, 0)

        reserve_resp = provider.reserve_contact(
            context=context,
            mission_profile_arn=test_mission_profile["mission_profile_arn"],
            satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/11111111-1111-1111-1111-000000025544",
            start_time=start_time,
            end_time=end_time,
            ground_station="Ohio Ground Station",
        )
        contact_id = reserve_resp["contactId"]

        # Cancel it
        response = provider.cancel_contact(context=context, contact_id=contact_id)

        assert response["contactId"] == contact_id

        # Verify the status changed
        contact = groundstation_stores.contacts[contact_id]
        assert contact.contact_status == ContactStatus.CANCELLED

    def test_cancel_nonexistent_contact(self, provider, context):
        """Test canceling a non-existent contact."""
        with pytest.raises(ResourceNotFoundException):
            provider.cancel_contact(context=context, contact_id="nonexistent-contact-id")

    def test_cancel_already_cancelled_contact(self, provider, context, test_mission_profile):
        """Test that canceling an already cancelled contact raises an error."""
        # Reserve and cancel a contact
        start_time = datetime(2026, 12, 31, 12, 0, 0)
        end_time = datetime(2026, 12, 31, 13, 0, 0)

        reserve_resp = provider.reserve_contact(
            context=context,
            mission_profile_arn=test_mission_profile["mission_profile_arn"],
            satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/11111111-1111-1111-1111-000000025544",
            start_time=start_time,
            end_time=end_time,
            ground_station="Ohio Ground Station",
        )
        contact_id = reserve_resp["contactId"]

        # Cancel it once
        provider.cancel_contact(context=context, contact_id=contact_id)

        # Try to cancel it again (should fail)
        with pytest.raises(InvalidParameterException) as exc:
            provider.cancel_contact(context=context, contact_id=contact_id)

        assert "Cannot cancel contact in CANCELLED state" in str(exc.value)

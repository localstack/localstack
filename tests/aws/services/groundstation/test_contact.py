"""Integration tests for Ground Station Contact operations.

Tests contact reservation, cancellation, and lifecycle state transitions.
"""

from datetime import datetime, timedelta

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers


@markers.aws.validated
class TestContactReserve:
    """Test ReserveContact operation."""

    def test_reserve_contact(self, aws_client):
        """Test reserving a contact."""
        # Create mission profile
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-contact",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="mp-for-contact",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        # Reserve contact
        start_time = datetime.utcnow() + timedelta(hours=1)
        end_time = start_time + timedelta(minutes=10)

        response = aws_client.groundstation.reserve_contact(
            missionProfileArn=mp_response["missionProfileArn"],
            satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/25544",
            startTime=start_time,
            endTime=end_time,
            groundStation="Ohio Ground Station",
        )

        assert "contactId" in response
        assert response["contactId"]

    def test_reserve_contact_with_tags(self, aws_client):
        """Test reserving a contact with tags."""
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-contact-tags",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="mp-for-contact-tags",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        start_time = datetime.utcnow() + timedelta(hours=1)
        end_time = start_time + timedelta(minutes=10)

        response = aws_client.groundstation.reserve_contact(
            missionProfileArn=mp_response["missionProfileArn"],
            satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/25544",
            startTime=start_time,
            endTime=end_time,
            groundStation="Ohio Ground Station",
            tags={"ContactType": "Downlink", "Priority": "High"},
        )

        assert "contactId" in response

    def test_reserve_contact_invalid_time_range(self, aws_client):
        """Test reserving contact with invalid time range (end before start)."""
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-invalid-time",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="mp-for-invalid-time",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        start_time = datetime.utcnow() + timedelta(hours=1)
        end_time = start_time - timedelta(minutes=10)  # Invalid: before start

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.reserve_contact(
                missionProfileArn=mp_response["missionProfileArn"],
                satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/25544",
                startTime=start_time,
                endTime=end_time,
                groundStation="Ohio Ground Station",
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_reserve_contact_past_time(self, aws_client):
        """Test reserving contact in the past (should fail)."""
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-past-time",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="mp-for-past-time",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        start_time = datetime.utcnow() - timedelta(hours=1)  # Past
        end_time = start_time + timedelta(minutes=10)

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.reserve_contact(
                missionProfileArn=mp_response["missionProfileArn"],
                satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/25544",
                startTime=start_time,
                endTime=end_time,
                groundStation="Ohio Ground Station",
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_reserve_contact_invalid_satellite(self, aws_client):
        """Test reserving contact with invalid satellite ARN."""
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-invalid-sat",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="mp-for-invalid-sat",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        start_time = datetime.utcnow() + timedelta(hours=1)
        end_time = start_time + timedelta(minutes=10)

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.reserve_contact(
                missionProfileArn=mp_response["missionProfileArn"],
                satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/99999",
                startTime=start_time,
                endTime=end_time,
                groundStation="Ohio Ground Station",
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"

    def test_reserve_contact_invalid_ground_station(self, aws_client):
        """Test reserving contact with invalid ground station."""
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-invalid-gs",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="mp-for-invalid-gs",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        start_time = datetime.utcnow() + timedelta(hours=1)
        end_time = start_time + timedelta(minutes=10)

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.reserve_contact(
                missionProfileArn=mp_response["missionProfileArn"],
                satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/25544",
                startTime=start_time,
                endTime=end_time,
                groundStation="NonExistentGroundStation",
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"


@markers.aws.validated
class TestContactDescribe:
    """Test DescribeContact operation."""

    def test_describe_contact(self, aws_client):
        """Test describing a contact."""
        # Create and reserve contact
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-describe",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="mp-for-describe",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        start_time = datetime.utcnow() + timedelta(hours=1)
        end_time = start_time + timedelta(minutes=10)

        reserve_response = aws_client.groundstation.reserve_contact(
            missionProfileArn=mp_response["missionProfileArn"],
            satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/25544",
            startTime=start_time,
            endTime=end_time,
            groundStation="Ohio Ground Station",
        )
        contact_id = reserve_response["contactId"]

        # Describe contact
        describe_response = aws_client.groundstation.describe_contact(contactId=contact_id)

        assert describe_response["contactId"] == contact_id
        assert "contactStatus" in describe_response
        assert describe_response["contactStatus"] in [
            "SCHEDULING",
            "SCHEDULED",
            "PASS",
            "COMPLETED",
            "FAILED",
            "CANCELLED",
        ]
        assert "startTime" in describe_response
        assert "endTime" in describe_response
        assert "satelliteArn" in describe_response
        assert "groundStation" in describe_response
        assert "missionProfileArn" in describe_response

    def test_describe_contact_not_found(self, aws_client):
        """Test describing a non-existent contact."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.describe_contact(
                contactId="00000000-0000-0000-0000-000000000000"
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"


@markers.aws.validated
class TestContactCancel:
    """Test CancelContact operation."""

    def test_cancel_contact(self, aws_client):
        """Test cancelling a scheduled contact."""
        # Create and reserve contact
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-cancel",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="mp-for-cancel",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        start_time = datetime.utcnow() + timedelta(hours=2)
        end_time = start_time + timedelta(minutes=10)

        reserve_response = aws_client.groundstation.reserve_contact(
            missionProfileArn=mp_response["missionProfileArn"],
            satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/25544",
            startTime=start_time,
            endTime=end_time,
            groundStation="Ohio Ground Station",
        )
        contact_id = reserve_response["contactId"]

        # Cancel contact
        cancel_response = aws_client.groundstation.cancel_contact(contactId=contact_id)

        assert cancel_response["contactId"] == contact_id

        # Verify status changed to CANCELLED
        describe_response = aws_client.groundstation.describe_contact(contactId=contact_id)
        assert describe_response["contactStatus"] == "CANCELLED"

    def test_cancel_contact_not_found(self, aws_client):
        """Test cancelling a non-existent contact."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.cancel_contact(
                contactId="00000000-0000-0000-0000-000000000000"
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"

    def test_cancel_completed_contact(self, aws_client):
        """Test cancelling a completed contact (should fail)."""
        # This test requires a contact that has already completed
        # In practice, this would require time manipulation or mocking
        # For now, we'll skip this test with a note
        pytest.skip("Requires time manipulation to test completed contact cancellation")


@markers.aws.validated
class TestContactList:
    """Test ListContacts operation."""

    def test_list_contacts(self, aws_client):
        """Test listing contacts."""
        # Create and reserve multiple contacts
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-list-contacts",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="mp-for-list-contacts",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        contact_ids = []
        for i in range(3):
            start_time = datetime.utcnow() + timedelta(hours=i + 1)
            end_time = start_time + timedelta(minutes=10)

            response = aws_client.groundstation.reserve_contact(
                missionProfileArn=mp_response["missionProfileArn"],
                satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/25544",
                startTime=start_time,
                endTime=end_time,
                groundStation="Ohio Ground Station",
            )
            contact_ids.append(response["contactId"])

        # List contacts
        list_start = datetime.utcnow()
        list_end = datetime.utcnow() + timedelta(days=1)

        list_response = aws_client.groundstation.list_contacts(
            statusList=["SCHEDULING", "SCHEDULED"],
            startTime=list_start,
            endTime=list_end,
        )

        assert "contactList" in list_response
        listed_ids = [c["contactId"] for c in list_response["contactList"]]

        for contact_id in contact_ids:
            assert contact_id in listed_ids

    def test_list_contacts_with_filters(self, aws_client):
        """Test listing contacts with status and ground station filters."""
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-list-filters",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="mp-for-list-filters",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        # Reserve and cancel one contact
        start_time = datetime.utcnow() + timedelta(hours=1)
        end_time = start_time + timedelta(minutes=10)

        reserve_response = aws_client.groundstation.reserve_contact(
            missionProfileArn=mp_response["missionProfileArn"],
            satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/25544",
            startTime=start_time,
            endTime=end_time,
            groundStation="Ohio Ground Station",
        )
        contact_id = reserve_response["contactId"]

        aws_client.groundstation.cancel_contact(contactId=contact_id)

        # List only cancelled contacts
        list_response = aws_client.groundstation.list_contacts(
            statusList=["CANCELLED"],
            startTime=datetime.utcnow(),
            endTime=datetime.utcnow() + timedelta(days=1),
            groundStation="Ohio Ground Station",
        )

        cancelled_ids = [c["contactId"] for c in list_response["contactList"]]
        assert contact_id in cancelled_ids

    def test_list_contacts_pagination(self, aws_client):
        """Test listing contacts with pagination."""
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-pagination-contacts",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="mp-for-pagination-contacts",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        for i in range(5):
            start_time = datetime.utcnow() + timedelta(hours=i + 1)
            end_time = start_time + timedelta(minutes=10)

            aws_client.groundstation.reserve_contact(
                missionProfileArn=mp_response["missionProfileArn"],
                satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/25544",
                startTime=start_time,
                endTime=end_time,
                groundStation="Ohio Ground Station",
            )

        # List with pagination
        list_response = aws_client.groundstation.list_contacts(
            statusList=["SCHEDULING", "SCHEDULED"],
            startTime=datetime.utcnow(),
            endTime=datetime.utcnow() + timedelta(days=1),
            maxResults=2,
        )

        assert len(list_response["contactList"]) <= 2
        if "nextToken" in list_response:
            next_response = aws_client.groundstation.list_contacts(
                statusList=["SCHEDULING", "SCHEDULED"],
                startTime=datetime.utcnow(),
                endTime=datetime.utcnow() + timedelta(days=1),
                maxResults=2,
                nextToken=list_response["nextToken"],
            )
            assert "contactList" in next_response

"""Integration tests for Ground Station Mission Profile operations.

Tests CRUD operations for mission profiles with dataflow edge validation.
"""

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers


@markers.aws.validated
class TestMissionProfileCreate:
    """Test CreateMissionProfile operation."""

    def test_create_mission_profile(self, aws_client):
        """Test creating a mission profile with valid dataflow edges."""
        # Create required configs first
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-mp",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        downlink_config = aws_client.groundstation.create_config(
            name="downlink-for-mp",
            configData={
                "antennaDownlinkConfig": {
                    "spectrumConfig": {
                        "centerFrequency": {"value": 2200.0, "units": "MHz"},
                        "bandwidth": {"value": 125.0, "units": "MHz"},
                    }
                }
            },
        )
        dataflow_config = aws_client.groundstation.create_config(
            name="dataflow-for-mp",
            configData={
                "dataflowEndpointConfig": {
                    "dataflowEndpointName": "test-endpoint",
                    "dataflowEndpointRegion": "us-east-1",
                }
            },
        )

        # Create mission profile
        response = aws_client.groundstation.create_mission_profile(
            name="test-mission-profile",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[
                [tracking_config["configArn"], downlink_config["configArn"]],
                [downlink_config["configArn"], dataflow_config["configArn"]],
            ],
            trackingConfigArn=tracking_config["configArn"],
        )

        assert "missionProfileId" in response
        assert "missionProfileArn" in response
        assert "arn:aws:groundstation" in response["missionProfileArn"]

    def test_create_mission_profile_with_tags(self, aws_client):
        """Test creating a mission profile with tags."""
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-mp-tags",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )

        response = aws_client.groundstation.create_mission_profile(
            name="test-mp-with-tags",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
            tags={"Mission": "TestSat", "Environment": "Dev"},
        )

        assert "missionProfileId" in response
        mp_arn = response["missionProfileArn"]

        # Verify tags
        tags_response = aws_client.groundstation.list_tags_for_resource(resourceArn=mp_arn)
        assert tags_response["tags"]["Mission"] == "TestSat"
        assert tags_response["tags"]["Environment"] == "Dev"

    def test_create_mission_profile_invalid_duration(self, aws_client):
        """Test creating mission profile with invalid contact duration."""
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-invalid-duration",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_mission_profile(
                name="test-invalid-duration",
                contactPrePassDurationSeconds=-1,  # Invalid
                contactPostPassDurationSeconds=120,
                minimumViableContactDurationSeconds=60,
                dataflowEdges=[],
                trackingConfigArn=tracking_config["configArn"],
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_create_mission_profile_invalid_dataflow_edge(self, aws_client):
        """Test creating mission profile with invalid dataflow edge order."""
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-invalid-edge",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        dataflow_config = aws_client.groundstation.create_config(
            name="dataflow-for-invalid-edge",
            configData={
                "dataflowEndpointConfig": {
                    "dataflowEndpointName": "test-endpoint",
                    "dataflowEndpointRegion": "us-east-1",
                }
            },
        )

        # Invalid: dataflow endpoint cannot come before tracking
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_mission_profile(
                name="test-invalid-edge",
                contactPrePassDurationSeconds=120,
                contactPostPassDurationSeconds=120,
                minimumViableContactDurationSeconds=60,
                dataflowEdges=[[dataflow_config["configArn"], tracking_config["configArn"]]],
                trackingConfigArn=tracking_config["configArn"],
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"


@markers.aws.validated
class TestMissionProfileGet:
    """Test GetMissionProfile operation."""

    def test_get_mission_profile(self, aws_client):
        """Test retrieving a mission profile."""
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-get",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )

        create_response = aws_client.groundstation.create_mission_profile(
            name="test-get-mp",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )
        mp_id = create_response["missionProfileId"]

        # Get mission profile
        get_response = aws_client.groundstation.get_mission_profile(missionProfileId=mp_id)

        assert get_response["missionProfileId"] == mp_id
        assert get_response["name"] == "test-get-mp"
        assert get_response["contactPrePassDurationSeconds"] == 120
        assert get_response["contactPostPassDurationSeconds"] == 120
        assert get_response["minimumViableContactDurationSeconds"] == 60
        assert "missionProfileArn" in get_response
        assert "dataflowEdges" in get_response
        assert "trackingConfigArn" in get_response

    def test_get_mission_profile_not_found(self, aws_client):
        """Test getting a non-existent mission profile."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.get_mission_profile(
                missionProfileId="00000000-0000-0000-0000-000000000000"
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"


@markers.aws.validated
class TestMissionProfileUpdate:
    """Test UpdateMissionProfile operation."""

    def test_update_mission_profile(self, aws_client):
        """Test updating a mission profile."""
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-update",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )

        create_response = aws_client.groundstation.create_mission_profile(
            name="test-update-mp",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )
        mp_id = create_response["missionProfileId"]

        # Update mission profile
        update_response = aws_client.groundstation.update_mission_profile(
            missionProfileId=mp_id,
            name="test-update-mp-modified",
            contactPrePassDurationSeconds=180,
            minimumViableContactDurationSeconds=90,
        )

        assert update_response["missionProfileId"] == mp_id

        # Verify update
        get_response = aws_client.groundstation.get_mission_profile(missionProfileId=mp_id)
        assert get_response["name"] == "test-update-mp-modified"
        assert get_response["contactPrePassDurationSeconds"] == 180
        assert get_response["minimumViableContactDurationSeconds"] == 90

    def test_update_mission_profile_not_found(self, aws_client):
        """Test updating a non-existent mission profile."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.update_mission_profile(
                missionProfileId="00000000-0000-0000-0000-000000000000",
                name="test-update",
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"


@markers.aws.validated
class TestMissionProfileDelete:
    """Test DeleteMissionProfile operation."""

    def test_delete_mission_profile(self, aws_client):
        """Test deleting a mission profile."""
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-delete",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )

        create_response = aws_client.groundstation.create_mission_profile(
            name="test-delete-mp",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )
        mp_id = create_response["missionProfileId"]

        # Delete mission profile
        delete_response = aws_client.groundstation.delete_mission_profile(missionProfileId=mp_id)

        assert delete_response["missionProfileId"] == mp_id

        # Verify deletion
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.get_mission_profile(missionProfileId=mp_id)
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"

    def test_delete_mission_profile_not_found(self, aws_client):
        """Test deleting a non-existent mission profile."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.delete_mission_profile(
                missionProfileId="00000000-0000-0000-0000-000000000000"
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"


@markers.aws.validated
class TestMissionProfileList:
    """Test ListMissionProfiles operation."""

    def test_list_mission_profiles(self, aws_client):
        """Test listing mission profiles."""
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-list",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )

        mp1 = aws_client.groundstation.create_mission_profile(
            name="test-list-mp-1",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )
        mp2 = aws_client.groundstation.create_mission_profile(
            name="test-list-mp-2",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        # List mission profiles
        response = aws_client.groundstation.list_mission_profiles()

        mp_ids = [mp["missionProfileId"] for mp in response["missionProfileList"]]
        assert mp1["missionProfileId"] in mp_ids
        assert mp2["missionProfileId"] in mp_ids

        # Verify structure
        for mp in response["missionProfileList"]:
            assert "missionProfileId" in mp
            assert "missionProfileArn" in mp
            assert "name" in mp
            assert "region" in mp

    def test_list_mission_profiles_pagination(self, aws_client):
        """Test listing mission profiles with pagination."""
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-pagination",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )

        for i in range(3):
            aws_client.groundstation.create_mission_profile(
                name=f"test-pagination-mp-{i}",
                contactPrePassDurationSeconds=120,
                contactPostPassDurationSeconds=120,
                minimumViableContactDurationSeconds=60,
                dataflowEdges=[],
                trackingConfigArn=tracking_config["configArn"],
            )

        # List with max results
        response = aws_client.groundstation.list_mission_profiles(maxResults=2)

        assert len(response["missionProfileList"]) <= 2
        if "nextToken" in response:
            next_response = aws_client.groundstation.list_mission_profiles(
                maxResults=2, nextToken=response["nextToken"]
            )
            assert "missionProfileList" in next_response

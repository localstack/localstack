"""Integration tests for error handling and edge cases.

Tests comprehensive error scenarios across all Ground Station operations.
"""

from datetime import datetime, timedelta

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers


@markers.aws.validated
class TestResourceNotFoundErrors:
    """Test ResourceNotFoundException for all resource types."""

    def test_get_nonexistent_config(self, aws_client):
        """Test getting non-existent config raises ResourceNotFoundException."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.get_config(
                configId="00000000-0000-0000-0000-000000000000",
                configType="tracking",
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"
        assert "config" in exc.value.response["Error"]["Message"].lower()

    def test_get_nonexistent_mission_profile(self, aws_client):
        """Test getting non-existent mission profile raises ResourceNotFoundException."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.get_mission_profile(
                missionProfileId="00000000-0000-0000-0000-000000000000"
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"

    def test_describe_nonexistent_contact(self, aws_client):
        """Test describing non-existent contact raises ResourceNotFoundException."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.describe_contact(
                contactId="00000000-0000-0000-0000-000000000000"
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"

    def test_get_nonexistent_dataflow_endpoint_group(self, aws_client):
        """Test getting non-existent dataflow endpoint group raises ResourceNotFoundException."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.get_dataflow_endpoint_group(
                dataflowEndpointGroupId="00000000-0000-0000-0000-000000000000"
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"

    def test_get_nonexistent_satellite(self, aws_client):
        """Test getting non-existent satellite raises ResourceNotFoundException."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.get_satellite(satelliteId="99999")
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"


@markers.aws.validated
class TestInvalidParameterErrors:
    """Test InvalidParameterException for various invalid inputs."""

    def test_invalid_frequency_range(self, aws_client):
        """Test config with frequency outside valid range."""
        # Frequency too high (> 30 GHz)
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_config(
                name="invalid-freq",
                configData={
                    "antennaDownlinkConfig": {
                        "spectrumConfig": {
                            "centerFrequency": {"value": 50000.0, "units": "MHz"},
                            "bandwidth": {"value": 125.0, "units": "MHz"},
                        }
                    }
                },
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_negative_bandwidth(self, aws_client):
        """Test config with negative bandwidth."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_config(
                name="negative-bandwidth",
                configData={
                    "antennaDownlinkConfig": {
                        "spectrumConfig": {
                            "centerFrequency": {"value": 2200.0, "units": "MHz"},
                            "bandwidth": {"value": -10.0, "units": "MHz"},
                        }
                    }
                },
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_invalid_eirp_value(self, aws_client):
        """Test uplink config with invalid EIRP."""
        # EIRP too high
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_config(
                name="invalid-eirp",
                configData={
                    "antennaUplinkConfig": {
                        "spectrumConfig": {
                            "centerFrequency": {"value": 2025.0, "units": "MHz"},
                            "polarization": "RIGHT_HAND",
                        },
                        "targetEirp": {"value": 100.0, "units": "dBW"},
                    }
                },
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_invalid_contact_time_range(self, aws_client):
        """Test contact reservation with end time before start time."""
        tracking_config = aws_client.groundstation.create_config(
            name="time-range-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="time-range-mp",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        start_time = datetime.utcnow() + timedelta(hours=1)
        end_time = start_time - timedelta(minutes=10)  # Before start

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.reserve_contact(
                missionProfileArn=mp_response["missionProfileArn"],
                satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/25544",
                startTime=start_time,
                endTime=end_time,
                groundStation="Ohio Ground Station",
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_past_contact_time(self, aws_client):
        """Test contact reservation in the past."""
        tracking_config = aws_client.groundstation.create_config(
            name="past-time-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="past-time-mp",
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

    def test_negative_contact_duration(self, aws_client):
        """Test mission profile with negative contact durations."""
        tracking_config = aws_client.groundstation.create_config(
            name="negative-duration-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_mission_profile(
                name="negative-duration-mp",
                contactPrePassDurationSeconds=-1,
                contactPostPassDurationSeconds=120,
                minimumViableContactDurationSeconds=60,
                dataflowEdges=[],
                trackingConfigArn=tracking_config["configArn"],
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_invalid_month_in_minute_usage(self, aws_client):
        """Test GetMinuteUsage with invalid month."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.get_minute_usage(month=13, year=2025)
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.get_minute_usage(month=0, year=2025)
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_cancel_already_cancelled_contact(self, aws_client):
        """Test cancelling an already cancelled contact."""
        tracking_config = aws_client.groundstation.create_config(
            name="double-cancel-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="double-cancel-mp",
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

        # Cancel once (should succeed)
        aws_client.groundstation.cancel_contact(contactId=contact_id)

        # Cancel again (should fail)
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.cancel_contact(contactId=contact_id)
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"


@markers.aws.validated
class TestDependencyErrors:
    """Test DependencyException when resources are in use."""

    def test_delete_config_in_use_by_mission_profile(self, aws_client):
        """Test deleting config that's used by a mission profile."""
        tracking_config = aws_client.groundstation.create_config(
            name="in-use-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )

        # Create mission profile using the config
        aws_client.groundstation.create_mission_profile(
            name="using-config-mp",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        # Try to delete config (should fail)
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.delete_config(
                configId=tracking_config["configId"],
                configType=tracking_config["configType"],
            )
        assert exc.value.response["Error"]["Code"] == "DependencyException"

    def test_delete_mission_profile_with_scheduled_contact(self, aws_client):
        """Test deleting mission profile with scheduled contact."""
        tracking_config = aws_client.groundstation.create_config(
            name="scheduled-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="scheduled-mp",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        # Reserve contact
        start_time = datetime.utcnow() + timedelta(hours=1)
        end_time = start_time + timedelta(minutes=10)

        aws_client.groundstation.reserve_contact(
            missionProfileArn=mp_response["missionProfileArn"],
            satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/25544",
            startTime=start_time,
            endTime=end_time,
            groundStation="Ohio Ground Station",
        )

        # Try to delete mission profile (should fail)
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.delete_mission_profile(
                missionProfileId=mp_response["missionProfileId"]
            )
        assert exc.value.response["Error"]["Code"] == "DependencyException"


@markers.aws.validated
class TestValidationErrors:
    """Test ValidationException for input validation failures."""

    def test_tag_key_too_long(self, aws_client):
        """Test tag key exceeding 128 character limit."""
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        config_response = aws_client.groundstation.create_config(
            name="long-tag-key", configData=config_data
        )

        long_key = "a" * 129  # Exceeds limit

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.tag_resource(
                resourceArn=config_response["configArn"], tags={long_key: "value"}
            )
        assert exc.value.response["Error"]["Code"] == "ValidationException"

    def test_tag_value_too_long(self, aws_client):
        """Test tag value exceeding 256 character limit."""
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        config_response = aws_client.groundstation.create_config(
            name="long-tag-value", configData=config_data
        )

        long_value = "a" * 257  # Exceeds limit

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.tag_resource(
                resourceArn=config_response["configArn"], tags={"key": long_value}
            )
        assert exc.value.response["Error"]["Code"] == "ValidationException"

    def test_too_many_tags(self, aws_client):
        """Test exceeding 50 tag limit."""
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        config_response = aws_client.groundstation.create_config(
            name="too-many-tags", configData=config_data
        )

        # 51 tags exceeds limit
        too_many_tags = {f"Key{i}": f"Value{i}" for i in range(51)}

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.tag_resource(
                resourceArn=config_response["configArn"], tags=too_many_tags
            )
        assert exc.value.response["Error"]["Code"] == "ValidationException"

    def test_empty_tag_key(self, aws_client):
        """Test tag with empty key."""
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        config_response = aws_client.groundstation.create_config(
            name="empty-tag-key", configData=config_data
        )

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.tag_resource(
                resourceArn=config_response["configArn"], tags={"": "value"}
            )
        assert exc.value.response["Error"]["Code"] == "ValidationException"

    def test_invalid_autotrack_value(self, aws_client):
        """Test tracking config with invalid autotrack value."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_config(
                name="invalid-autotrack",
                configData={"trackingConfig": {"autotrack": "INVALID"}},
            )
        assert exc.value.response["Error"]["Code"] == "ValidationException"

    def test_invalid_polarization_value(self, aws_client):
        """Test uplink config with invalid polarization."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_config(
                name="invalid-polarization",
                configData={
                    "antennaUplinkConfig": {
                        "spectrumConfig": {
                            "centerFrequency": {"value": 2025.0, "units": "MHz"},
                            "polarization": "INVALID_POLARIZATION",
                        },
                        "targetEirp": {"value": 20.0, "units": "dBW"},
                    }
                },
            )
        assert exc.value.response["Error"]["Code"] == "ValidationException"


@markers.aws.validated
class TestARNValidation:
    """Test ARN format validation across operations."""

    def test_malformed_config_arn_in_dataflow_edge(self, aws_client):
        """Test mission profile creation with malformed config ARN."""
        tracking_config = aws_client.groundstation.create_config(
            name="arn-test-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )

        malformed_arn = "invalid-arn-format"

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_mission_profile(
                name="malformed-arn-mp",
                contactPrePassDurationSeconds=120,
                contactPostPassDurationSeconds=120,
                minimumViableContactDurationSeconds=60,
                dataflowEdges=[[tracking_config["configArn"], malformed_arn]],
                trackingConfigArn=tracking_config["configArn"],
            )
        assert exc.value.response["Error"]["Code"] in [
            "ValidationException",
            "InvalidParameterException",
        ]

    def test_wrong_region_in_arn(self, aws_client):
        """Test using ARN from different region."""
        # This test would require multi-region setup
        # For now, just verify ARN format is checked
        tracking_config = aws_client.groundstation.create_config(
            name="region-arn-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )

        # ARN from different region
        wrong_region_arn = "arn:aws:groundstation:eu-west-1:123456789012:config/tracking/12345678-1234-1234-1234-123456789012"

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_mission_profile(
                name="wrong-region-mp",
                contactPrePassDurationSeconds=120,
                contactPostPassDurationSeconds=120,
                minimumViableContactDurationSeconds=60,
                dataflowEdges=[[tracking_config["configArn"], wrong_region_arn]],
                trackingConfigArn=tracking_config["configArn"],
            )
        assert exc.value.response["Error"]["Code"] in [
            "ResourceNotFoundException",
            "InvalidParameterException",
        ]


@markers.aws.validated
class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_zero_duration_contact(self, aws_client):
        """Test contact with zero duration."""
        tracking_config = aws_client.groundstation.create_config(
            name="zero-duration-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="zero-duration-mp",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        start_time = datetime.utcnow() + timedelta(hours=1)
        end_time = start_time  # Zero duration

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.reserve_contact(
                missionProfileArn=mp_response["missionProfileArn"],
                satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/25544",
                startTime=start_time,
                endTime=end_time,
                groundStation="Ohio Ground Station",
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_list_contacts_with_invalid_time_range(self, aws_client):
        """Test ListContacts with end before start."""
        start_time = datetime.utcnow()
        end_time = start_time - timedelta(days=1)  # Before start

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.list_contacts(
                statusList=["SCHEDULED"], startTime=start_time, endTime=end_time
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_extremely_long_mission_profile_name(self, aws_client):
        """Test mission profile with very long name."""
        tracking_config = aws_client.groundstation.create_config(
            name="long-name-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )

        # AWS typically limits names to 256 characters
        long_name = "a" * 300

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_mission_profile(
                name=long_name,
                contactPrePassDurationSeconds=120,
                contactPostPassDurationSeconds=120,
                minimumViableContactDurationSeconds=60,
                dataflowEdges=[],
                trackingConfigArn=tracking_config["configArn"],
            )
        assert exc.value.response["Error"]["Code"] == "ValidationException"

    def test_maximum_pagination_limit(self, aws_client):
        """Test pagination with maximum limit."""
        # Test that maxResults is capped
        response = aws_client.groundstation.list_configs(maxResults=1000)
        assert "configList" in response
        # AWS typically caps pagination at 100
        assert len(response["configList"]) <= 100

    def test_update_nonexistent_resource(self, aws_client):
        """Test updating non-existent resources."""
        # Update non-existent config
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.update_config(
                configId="00000000-0000-0000-0000-000000000000",
                configType="tracking",
                name="updated",
                configData={"trackingConfig": {"autotrack": "REQUIRED"}},
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"

        # Update non-existent mission profile
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.update_mission_profile(
                missionProfileId="00000000-0000-0000-0000-000000000000", name="updated"
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"

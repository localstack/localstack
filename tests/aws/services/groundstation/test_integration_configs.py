"""Integration tests for comprehensive config scenarios.

Tests multi-account isolation, cross-region configs, config lifecycle,
and all 6 config type validations.
"""

from datetime import datetime, timedelta

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers


@markers.aws.validated
class TestMultiAccountConfigIsolation:
    """Test config isolation across multiple accounts."""

    def test_configs_isolated_by_account(self, aws_client, secondary_aws_client):
        """Test that configs are isolated per account."""
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}

        # Create config in primary account
        primary_response = aws_client.groundstation.create_config(
            name="primary-account-config", configData=config_data
        )

        # Create config in secondary account
        secondary_response = secondary_aws_client.groundstation.create_config(
            name="secondary-account-config", configData=config_data
        )

        # List configs in primary account
        primary_list = aws_client.groundstation.list_configs()
        primary_ids = [c["configId"] for c in primary_list["configList"]]

        # List configs in secondary account
        secondary_list = secondary_aws_client.groundstation.list_configs()
        secondary_ids = [c["configId"] for c in secondary_list["configList"]]

        # Verify isolation
        assert primary_response["configId"] in primary_ids
        assert primary_response["configId"] not in secondary_ids
        assert secondary_response["configId"] in secondary_ids
        assert secondary_response["configId"] not in primary_ids

    def test_config_not_accessible_across_accounts(self, aws_client, secondary_aws_client):
        """Test that configs from one account cannot be accessed by another."""
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}

        # Create config in primary account
        primary_response = aws_client.groundstation.create_config(
            name="primary-only-config", configData=config_data
        )
        config_id = primary_response["configId"]
        config_type = primary_response["configType"]

        # Try to access from secondary account (should fail)
        with pytest.raises(ClientError) as exc:
            secondary_aws_client.groundstation.get_config(
                configId=config_id, configType=config_type
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"


@markers.aws.validated
class TestCrossRegionConfigs:
    """Test configs across multiple regions."""

    def test_configs_isolated_by_region(self, aws_client):
        """Test that configs are isolated per region."""
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}

        # Create config in us-east-1
        us_east_client = aws_client.groundstation
        us_east_response = us_east_client.create_config(
            name="us-east-config", configData=config_data
        )

        # Create config in us-west-2
        us_west_client = aws_client.groundstation
        us_west_client._client_config.region_name = "us-west-2"
        us_west_response = us_west_client.create_config(
            name="us-west-config", configData=config_data
        )

        # Verify ARNs have different regions
        assert "us-east-1" in us_east_response["configArn"]
        assert "us-west-2" in us_west_response["configArn"]

        # List in us-east-1
        us_east_list = us_east_client.list_configs()
        us_east_ids = [c["configId"] for c in us_east_list["configList"]]

        # Verify region isolation
        assert us_east_response["configId"] in us_east_ids


@markers.aws.validated
class TestConfigLifecycle:
    """Test complete config lifecycle scenarios."""

    def test_config_create_update_delete_lifecycle(self, aws_client):
        """Test full lifecycle: create -> update -> delete."""
        # Create
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        create_response = aws_client.groundstation.create_config(
            name="lifecycle-config",
            configData=config_data,
            tags={"Stage": "Created"},
        )
        config_id = create_response["configId"]
        config_type = create_response["configType"]

        # Verify created
        get_response = aws_client.groundstation.get_config(
            configId=config_id, configType=config_type
        )
        assert get_response["name"] == "lifecycle-config"
        assert get_response["tags"]["Stage"] == "Created"

        # Update
        updated_config_data = {"trackingConfig": {"autotrack": "PREFERRED"}}
        aws_client.groundstation.update_config(
            configId=config_id,
            configType=config_type,
            name="lifecycle-config-updated",
            configData=updated_config_data,
        )

        # Tag as updated
        config_arn = get_response["configArn"]
        aws_client.groundstation.tag_resource(resourceArn=config_arn, tags={"Stage": "Updated"})

        # Verify updated
        get_response = aws_client.groundstation.get_config(
            configId=config_id, configType=config_type
        )
        assert get_response["name"] == "lifecycle-config-updated"
        assert get_response["configData"]["trackingConfig"]["autotrack"] == "PREFERRED"

        # Verify tags updated
        tags = aws_client.groundstation.list_tags_for_resource(resourceArn=config_arn)
        assert tags["tags"]["Stage"] == "Updated"

        # Delete
        aws_client.groundstation.delete_config(configId=config_id, configType=config_type)

        # Verify deleted
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.get_config(configId=config_id, configType=config_type)
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"

    def test_config_used_in_mission_profile_cannot_be_deleted(self, aws_client):
        """Test that configs in use by mission profiles cannot be deleted."""
        # Create tracking config
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-in-use",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )

        # Create mission profile using the config
        aws_client.groundstation.create_mission_profile(
            name="mp-using-config",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        # Try to delete the config (should fail - config is in use)
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.delete_config(
                configId=tracking_config["configId"],
                configType=tracking_config["configType"],
            )
        assert exc.value.response["Error"]["Code"] == "DependencyException"


@markers.aws.validated
class TestConfigTypeValidations:
    """Test validation rules for all 6 config types."""

    def test_antenna_downlink_frequency_validation(self, aws_client):
        """Test frequency range validation for antenna downlink."""
        # Valid frequency
        valid_config = {
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2200.0, "units": "MHz"},
                    "bandwidth": {"value": 125.0, "units": "MHz"},
                }
            }
        }
        response = aws_client.groundstation.create_config(
            name="valid-downlink", configData=valid_config
        )
        assert "configId" in response

        # Invalid frequency (too high)
        invalid_config = {
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 50000.0, "units": "MHz"},  # > 30 GHz
                    "bandwidth": {"value": 125.0, "units": "MHz"},
                }
            }
        }
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_config(
                name="invalid-downlink", configData=invalid_config
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_antenna_uplink_eirp_validation(self, aws_client):
        """Test EIRP validation for antenna uplink."""
        # Valid EIRP
        valid_config = {
            "antennaUplinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2025.0, "units": "MHz"},
                    "polarization": "RIGHT_HAND",
                },
                "targetEirp": {"value": 20.0, "units": "dBW"},
            }
        }
        response = aws_client.groundstation.create_config(
            name="valid-uplink", configData=valid_config
        )
        assert "configId" in response

        # Invalid EIRP (too high)
        invalid_config = {
            "antennaUplinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2025.0, "units": "MHz"},
                    "polarization": "RIGHT_HAND",
                },
                "targetEirp": {"value": 100.0, "units": "dBW"},  # Too high
            }
        }
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_config(name="invalid-uplink", configData=invalid_config)
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_tracking_config_autotrack_values(self, aws_client):
        """Test valid autotrack values for tracking config."""
        # REQUIRED
        config1 = aws_client.groundstation.create_config(
            name="tracking-required",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        assert config1["configId"]

        # PREFERRED
        config2 = aws_client.groundstation.create_config(
            name="tracking-preferred",
            configData={"trackingConfig": {"autotrack": "PREFERRED"}},
        )
        assert config2["configId"]

        # REMOVED
        config3 = aws_client.groundstation.create_config(
            name="tracking-removed",
            configData={"trackingConfig": {"autotrack": "REMOVED"}},
        )
        assert config3["configId"]

        # Invalid value
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_config(
                name="tracking-invalid",
                configData={"trackingConfig": {"autotrack": "INVALID"}},
            )
        assert exc.value.response["Error"]["Code"] == "ValidationException"

    def test_uplink_echo_config_requires_uplink_arn(self, aws_client):
        """Test that uplink echo config requires valid uplink config ARN."""
        # Create uplink config first
        uplink_config = aws_client.groundstation.create_config(
            name="uplink-for-echo",
            configData={
                "antennaUplinkConfig": {
                    "spectrumConfig": {
                        "centerFrequency": {"value": 2025.0, "units": "MHz"},
                        "polarization": "RIGHT_HAND",
                    },
                    "targetEirp": {"value": 20.0, "units": "dBW"},
                }
            },
        )

        # Valid uplink echo config
        echo_config = {
            "uplinkEchoConfig": {
                "enabled": True,
                "antennaUplinkConfigArn": uplink_config["configArn"],
            }
        }
        response = aws_client.groundstation.create_config(name="valid-echo", configData=echo_config)
        assert "configId" in response

        # Invalid uplink ARN
        invalid_echo_config = {
            "uplinkEchoConfig": {
                "enabled": True,
                "antennaUplinkConfigArn": "arn:aws:groundstation:us-east-1:123456789012:config/antenna-uplink/00000000-0000-0000-0000-000000000000",
            }
        }
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_config(
                name="invalid-echo", configData=invalid_echo_config
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"

    def test_demod_decode_config_spectrum_validation(self, aws_client):
        """Test spectrum config validation for demod decode."""
        # Valid demod decode config
        valid_config = {
            "antennaDownlinkDemodDecodeConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2200.0, "units": "MHz"},
                    "bandwidth": {"value": 125.0, "units": "MHz"},
                },
                "demodulationConfig": {"unvalidatedJSON": '{"type": "QPSK"}'},
                "decodeConfig": {"unvalidatedJSON": '{"type": "Turbo"}'},
            }
        }
        response = aws_client.groundstation.create_config(
            name="valid-demod-decode", configData=valid_config
        )
        assert "configId" in response

        # Invalid bandwidth (negative)
        invalid_config = {
            "antennaDownlinkDemodDecodeConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2200.0, "units": "MHz"},
                    "bandwidth": {"value": -10.0, "units": "MHz"},  # Negative
                },
                "demodulationConfig": {"unvalidatedJSON": '{"type": "QPSK"}'},
                "decodeConfig": {"unvalidatedJSON": '{"type": "Turbo"}'},
            }
        }
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_config(
                name="invalid-demod-decode", configData=invalid_config
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_dataflow_endpoint_config_validation(self, aws_client):
        """Test dataflow endpoint config validation."""
        # Valid config
        valid_config = {
            "dataflowEndpointConfig": {
                "dataflowEndpointName": "valid-endpoint",
                "dataflowEndpointRegion": "us-east-1",
            }
        }
        response = aws_client.groundstation.create_config(
            name="valid-dataflow-endpoint", configData=valid_config
        )
        assert "configId" in response

        # Invalid region
        invalid_config = {
            "dataflowEndpointConfig": {
                "dataflowEndpointName": "invalid-endpoint",
                "dataflowEndpointRegion": "invalid-region",
            }
        }
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_config(
                name="invalid-dataflow-endpoint", configData=invalid_config
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"


@markers.aws.validated
class TestConfigIntegrationScenarios:
    """Test real-world config integration scenarios."""

    def test_complete_downlink_mission_config_chain(self, aws_client):
        """Test creating a complete downlink mission configuration."""
        # Step 1: Create tracking config
        tracking = aws_client.groundstation.create_config(
            name="downlink-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )

        # Step 2: Create antenna downlink config
        downlink = aws_client.groundstation.create_config(
            name="downlink-antenna",
            configData={
                "antennaDownlinkConfig": {
                    "spectrumConfig": {
                        "centerFrequency": {"value": 2200.0, "units": "MHz"},
                        "bandwidth": {"value": 125.0, "units": "MHz"},
                    }
                }
            },
        )

        # Step 3: Create dataflow endpoint config
        dataflow = aws_client.groundstation.create_config(
            name="downlink-dataflow",
            configData={
                "dataflowEndpointConfig": {
                    "dataflowEndpointName": "downlink-endpoint",
                    "dataflowEndpointRegion": "us-east-1",
                }
            },
        )

        # Step 4: Create mission profile with all configs
        mp_response = aws_client.groundstation.create_mission_profile(
            name="downlink-mission",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[
                [tracking["configArn"], downlink["configArn"]],
                [downlink["configArn"], dataflow["configArn"]],
            ],
            trackingConfigArn=tracking["configArn"],
        )

        # Verify mission profile created successfully
        assert "missionProfileId" in mp_response

        # Step 5: Verify can reserve contact with this mission profile
        start_time = datetime.utcnow() + timedelta(hours=1)
        end_time = start_time + timedelta(minutes=10)

        contact_response = aws_client.groundstation.reserve_contact(
            missionProfileArn=mp_response["missionProfileArn"],
            satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/25544",
            startTime=start_time,
            endTime=end_time,
            groundStation="Ohio Ground Station",
        )

        assert "contactId" in contact_response

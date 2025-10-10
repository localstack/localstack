"""Integration tests for Ground Station Config operations.

Tests CRUD operations for all 6 config types following AWS API contracts.
"""

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers


@markers.aws.validated
class TestConfigCreate:
    """Test CreateConfig operation for all config types."""

    def test_create_antenna_downlink_config(self, aws_client):
        """Test creating an antenna downlink config."""
        config_data = {
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2200.0, "units": "MHz"},
                    "bandwidth": {"value": 125.0, "units": "MHz"},
                }
            }
        }

        response = aws_client.groundstation.create_config(
            name="test-antenna-downlink", configData=config_data
        )

        assert "configId" in response
        assert "configArn" in response
        assert "configType" in response
        assert response["configType"] == "antenna-downlink"
        assert "arn:aws:groundstation" in response["configArn"]

    def test_create_antenna_downlink_demod_decode_config(self, aws_client):
        """Test creating an antenna downlink demod decode config."""
        config_data = {
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
            name="test-demod-decode", configData=config_data
        )

        assert "configId" in response
        assert response["configType"] == "antenna-downlink-demod-decode"

    def test_create_antenna_uplink_config(self, aws_client):
        """Test creating an antenna uplink config."""
        config_data = {
            "antennaUplinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2025.0, "units": "MHz"},
                    "polarization": "RIGHT_HAND",
                },
                "targetEirp": {"value": 20.0, "units": "dBW"},
            }
        }

        response = aws_client.groundstation.create_config(
            name="test-antenna-uplink", configData=config_data
        )

        assert "configId" in response
        assert response["configType"] == "antenna-uplink"

    def test_create_dataflow_endpoint_config(self, aws_client):
        """Test creating a dataflow endpoint config."""
        config_data = {
            "dataflowEndpointConfig": {
                "dataflowEndpointName": "test-endpoint",
                "dataflowEndpointRegion": "us-east-1",
            }
        }

        response = aws_client.groundstation.create_config(
            name="test-dataflow-endpoint", configData=config_data
        )

        assert "configId" in response
        assert response["configType"] == "dataflow-endpoint"

    def test_create_tracking_config(self, aws_client):
        """Test creating a tracking config."""
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}

        response = aws_client.groundstation.create_config(
            name="test-tracking", configData=config_data
        )

        assert "configId" in response
        assert response["configType"] == "tracking"

    def test_create_uplink_echo_config(self, aws_client):
        """Test creating an uplink echo config."""
        config_data = {
            "uplinkEchoConfig": {
                "enabled": True,
                "antennaUplinkConfigArn": "arn:aws:groundstation:us-east-1:123456789012:config/antenna-uplink/12345678-1234-1234-1234-123456789012",
            }
        }

        response = aws_client.groundstation.create_config(
            name="test-uplink-echo", configData=config_data
        )

        assert "configId" in response
        assert response["configType"] == "uplink-echo"

    def test_create_config_with_tags(self, aws_client):
        """Test creating a config with tags."""
        config_data = {
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2200.0, "units": "MHz"},
                    "bandwidth": {"value": 125.0, "units": "MHz"},
                }
            }
        }

        response = aws_client.groundstation.create_config(
            name="test-with-tags",
            configData=config_data,
            tags={"Environment": "Test", "Owner": "TeamA"},
        )

        assert "configId" in response
        config_arn = response["configArn"]

        # Verify tags were applied
        tags_response = aws_client.groundstation.list_tags_for_resource(resourceArn=config_arn)
        assert tags_response["tags"]["Environment"] == "Test"
        assert tags_response["tags"]["Owner"] == "TeamA"

    def test_create_config_invalid_frequency(self, aws_client):
        """Test creating config with invalid frequency (should fail validation)."""
        config_data = {
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 100000.0, "units": "MHz"},  # Too high
                    "bandwidth": {"value": 125.0, "units": "MHz"},
                }
            }
        }

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_config(
                name="test-invalid-frequency", configData=config_data
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_create_config_duplicate_name_allowed(self, aws_client):
        """Test that duplicate config names are allowed (configs are unique by ID)."""
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}

        response1 = aws_client.groundstation.create_config(
            name="duplicate-name", configData=config_data
        )
        response2 = aws_client.groundstation.create_config(
            name="duplicate-name", configData=config_data
        )

        # Both should succeed with different IDs
        assert response1["configId"] != response2["configId"]


@markers.aws.validated
class TestConfigGet:
    """Test GetConfig operation."""

    def test_get_config(self, aws_client):
        """Test retrieving a config by ID."""
        # Create a config first
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        create_response = aws_client.groundstation.create_config(
            name="test-get-config", configData=config_data
        )
        config_id = create_response["configId"]
        config_type = create_response["configType"]

        # Get the config
        get_response = aws_client.groundstation.get_config(
            configId=config_id, configType=config_type
        )

        assert get_response["configId"] == config_id
        assert get_response["name"] == "test-get-config"
        assert get_response["configType"] == config_type
        assert "configData" in get_response
        assert "configArn" in get_response
        assert "tags" in get_response

    def test_get_config_not_found(self, aws_client):
        """Test getting a non-existent config."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.get_config(
                configId="00000000-0000-0000-0000-000000000000",
                configType="tracking",
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"


@markers.aws.validated
class TestConfigUpdate:
    """Test UpdateConfig operation."""

    def test_update_config(self, aws_client):
        """Test updating a config."""
        # Create a config
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        create_response = aws_client.groundstation.create_config(
            name="test-update", configData=config_data
        )
        config_id = create_response["configId"]
        config_type = create_response["configType"]

        # Update the config
        updated_config_data = {"trackingConfig": {"autotrack": "PREFERRED"}}
        update_response = aws_client.groundstation.update_config(
            configId=config_id,
            configType=config_type,
            name="test-update-modified",
            configData=updated_config_data,
        )

        assert update_response["configId"] == config_id
        assert update_response["configType"] == config_type

        # Verify the update
        get_response = aws_client.groundstation.get_config(
            configId=config_id, configType=config_type
        )
        assert get_response["name"] == "test-update-modified"
        assert get_response["configData"]["trackingConfig"]["autotrack"] == "PREFERRED"

    def test_update_config_not_found(self, aws_client):
        """Test updating a non-existent config."""
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.update_config(
                configId="00000000-0000-0000-0000-000000000000",
                configType="tracking",
                name="test-update",
                configData=config_data,
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"


@markers.aws.validated
class TestConfigDelete:
    """Test DeleteConfig operation."""

    def test_delete_config(self, aws_client):
        """Test deleting a config."""
        # Create a config
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        create_response = aws_client.groundstation.create_config(
            name="test-delete", configData=config_data
        )
        config_id = create_response["configId"]
        config_type = create_response["configType"]

        # Delete the config
        delete_response = aws_client.groundstation.delete_config(
            configId=config_id, configType=config_type
        )

        assert delete_response["configId"] == config_id
        assert delete_response["configType"] == config_type
        assert delete_response["configArn"]

        # Verify it's deleted
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.get_config(configId=config_id, configType=config_type)
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"

    def test_delete_config_not_found(self, aws_client):
        """Test deleting a non-existent config."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.delete_config(
                configId="00000000-0000-0000-0000-000000000000",
                configType="tracking",
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"


@markers.aws.validated
class TestConfigList:
    """Test ListConfigs operation."""

    def test_list_configs_empty(self, aws_client):
        """Test listing configs when none exist."""
        response = aws_client.groundstation.list_configs()
        assert "configList" in response
        # May have configs from other tests, just verify structure
        assert isinstance(response["configList"], list)

    def test_list_configs(self, aws_client):
        """Test listing configs."""
        # Create multiple configs
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}

        config1 = aws_client.groundstation.create_config(name="test-list-1", configData=config_data)
        config2 = aws_client.groundstation.create_config(name="test-list-2", configData=config_data)

        # List configs
        response = aws_client.groundstation.list_configs()

        config_ids = [c["configId"] for c in response["configList"]]
        assert config1["configId"] in config_ids
        assert config2["configId"] in config_ids

        # Verify config structure
        for config in response["configList"]:
            assert "configId" in config
            assert "configType" in config
            assert "configArn" in config
            assert "name" in config

    def test_list_configs_pagination(self, aws_client):
        """Test listing configs with pagination."""
        # Create several configs
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        for i in range(5):
            aws_client.groundstation.create_config(
                name=f"test-pagination-{i}", configData=config_data
            )

        # List with max results
        response = aws_client.groundstation.list_configs(maxResults=2)

        assert len(response["configList"]) <= 2
        if "nextToken" in response:
            # Get next page
            next_response = aws_client.groundstation.list_configs(
                maxResults=2, nextToken=response["nextToken"]
            )
            assert "configList" in next_response

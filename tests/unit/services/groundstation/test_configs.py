"""Unit tests for Ground Station configuration operations."""

import pytest

from localstack.aws.api import RequestContext
from localstack.aws.api.groundstation import (
    ConfigCapabilityType,
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


class TestCreateConfig:
    """Tests for CreateConfig operation."""

    def test_create_antenna_downlink_config(self, provider, context):
        """Test creating an antenna downlink configuration."""
        config_data = {
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2200.0, "units": "MHz"},
                    "bandwidth": {"value": 125.0, "units": "MHz"},
                }
            }
        }

        response = provider.create_config(
            context=context, name="test-downlink", config_data=config_data
        )

        assert "configId" in response
        assert "configArn" in response
        assert response["configType"] == "antenna-downlink"
        assert response["configArn"].startswith(
            "arn:aws:groundstation:us-east-1:000000000000:config/antenna-downlink/"
        )

    def test_create_antenna_uplink_config(self, provider, context):
        """Test creating an antenna uplink configuration."""
        config_data = {
            "antennaUplinkConfig": {
                "spectrumConfig": {"centerFrequency": {"value": 8400.0, "units": "MHz"}},
                "targetEirp": {"value": 30.0, "units": "dBW"},
            }
        }

        response = provider.create_config(
            context=context, name="test-uplink", config_data=config_data
        )

        assert response["configType"] == "antenna-uplink"
        assert "configId" in response

    def test_create_tracking_config(self, provider, context):
        """Test creating a tracking configuration."""
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}

        response = provider.create_config(
            context=context, name="test-tracking", config_data=config_data
        )

        assert response["configType"] == "tracking"
        assert "configId" in response

    def test_create_dataflow_endpoint_config(self, provider, context):
        """Test creating a dataflow endpoint configuration."""
        config_data = {
            "dataflowEndpointConfig": {
                "dataflowEndpointName": "test-endpoint",
                "dataflowEndpointRegion": "us-east-1",
            }
        }

        response = provider.create_config(
            context=context, name="test-dataflow", config_data=config_data
        )

        assert response["configType"] == "dataflow-endpoint"
        assert "configId" in response

    def test_create_uplink_echo_config(self, provider, context):
        """Test creating an uplink echo configuration."""
        config_data = {
            "uplinkEchoConfig": {
                "enabled": True,
                "antennaUplinkConfigArn": "arn:aws:groundstation:us-east-1:000000000000:config/antenna-uplink/test",
            }
        }

        response = provider.create_config(
            context=context, name="test-uplink-echo", config_data=config_data
        )

        assert response["configType"] == "uplink-echo"
        assert "configId" in response

    def test_create_antenna_downlink_demod_decode_config(self, provider, context):
        """Test creating an antenna downlink demod decode configuration."""
        config_data = {
            "antennaDownlinkDemodDecodeConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2200.0, "units": "MHz"},
                    "bandwidth": {"value": 125.0, "units": "MHz"},
                },
                "demodulationConfig": {"unvalidatedJSON": '{"modulation": "QPSK"}'},
                "decodeConfig": {"unvalidatedJSON": '{"coding": "TURBO"}'},
            }
        }

        response = provider.create_config(
            context=context, name="test-demod-decode", config_data=config_data
        )

        assert response["configType"] == "antenna-downlink-demod-decode"
        assert "configId" in response

    def test_create_config_with_tags(self, provider, context):
        """Test creating a config with tags."""
        config_data = {
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2200.0, "units": "MHz"},
                    "bandwidth": {"value": 125.0, "units": "MHz"},
                }
            }
        }
        tags = {"Environment": "test", "Project": "groundstation"}

        response = provider.create_config(
            context=context, name="test-with-tags", config_data=config_data, tags=tags
        )

        config_arn = response["configArn"]
        assert config_arn in groundstation_stores.tags
        assert groundstation_stores.tags[config_arn] == tags

    def test_create_config_invalid_frequency(self, provider, context):
        """Test that invalid frequency is rejected."""
        config_data = {
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 1000.0, "units": "MHz"},  # Invalid
                    "bandwidth": {"value": 125.0, "units": "MHz"},
                }
            }
        }

        with pytest.raises(InvalidParameterException) as exc:
            provider.create_config(context=context, name="invalid-freq", config_data=config_data)

        assert "Frequency" in str(exc.value)
        assert "outside valid ranges" in str(exc.value)

    def test_create_config_invalid_eirp(self, provider, context):
        """Test that invalid EIRP is rejected."""
        config_data = {
            "antennaUplinkConfig": {
                "spectrumConfig": {"centerFrequency": {"value": 8400.0, "units": "MHz"}},
                "targetEirp": {"value": 100.0, "units": "dBW"},  # Invalid (too high)
            }
        }

        with pytest.raises(InvalidParameterException) as exc:
            provider.create_config(context=context, name="invalid-eirp", config_data=config_data)

        assert "EIRP" in str(exc.value)


class TestGetConfig:
    """Tests for GetConfig operation."""

    def test_get_existing_config(self, provider, context):
        """Test getting an existing configuration."""
        # Create a config first
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        create_response = provider.create_config(
            context=context, name="test-tracking", config_data=config_data
        )
        config_id = create_response["configId"]

        # Get the config
        response = provider.get_config(
            context=context, config_id=config_id, config_type=ConfigCapabilityType.tracking
        )

        assert response["configId"] == config_id
        assert response["name"] == "test-tracking"
        assert response["configType"] == "tracking"
        assert "configData" in response

    def test_get_nonexistent_config(self, provider, context):
        """Test getting a non-existent configuration."""
        with pytest.raises(ResourceNotFoundException) as exc:
            provider.get_config(
                context=context,
                config_id="nonexistent-id",
                config_type=ConfigCapabilityType.tracking,
            )

        assert "not found" in str(exc.value)


class TestUpdateConfig:
    """Tests for UpdateConfig operation."""

    def test_update_config_name(self, provider, context):
        """Test updating a config name."""
        # Create a config
        config_data = {
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2200.0, "units": "MHz"},
                    "bandwidth": {"value": 125.0, "units": "MHz"},
                }
            }
        }
        create_response = provider.create_config(
            context=context, name="original-name", config_data=config_data
        )
        config_id = create_response["configId"]

        # Update the name
        response = provider.update_config(
            context=context,
            config_id=config_id,
            config_type=ConfigCapabilityType.antenna_downlink,
            name="updated-name",
            config_data=config_data,
        )

        assert response["configId"] == config_id

        # Verify the update
        get_response = provider.get_config(
            context=context,
            config_id=config_id,
            config_type=ConfigCapabilityType.antenna_downlink,
        )
        assert get_response["name"] == "updated-name"

    def test_update_config_data(self, provider, context):
        """Test updating config data."""
        # Create a config
        original_data = {
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2200.0, "units": "MHz"},
                    "bandwidth": {"value": 125.0, "units": "MHz"},
                }
            }
        }
        create_response = provider.create_config(
            context=context, name="test-config", config_data=original_data
        )
        config_id = create_response["configId"]

        # Update with new frequency
        updated_data = {
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2250.0, "units": "MHz"},
                    "bandwidth": {"value": 150.0, "units": "MHz"},
                }
            }
        }
        provider.update_config(
            context=context,
            config_id=config_id,
            config_type=ConfigCapabilityType.antenna_downlink,
            name="test-config",
            config_data=updated_data,
        )

        # Verify the update
        get_response = provider.get_config(
            context=context,
            config_id=config_id,
            config_type=ConfigCapabilityType.antenna_downlink,
        )
        assert (
            get_response["configData"]["antennaDownlinkConfig"]["spectrumConfig"][
                "centerFrequency"
            ]["value"]
            == 2250.0
        )


class TestDeleteConfig:
    """Tests for DeleteConfig operation."""

    def test_delete_unused_config(self, provider, context):
        """Test deleting an unused configuration."""
        # Create a config
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        create_response = provider.create_config(
            context=context, name="test-tracking", config_data=config_data
        )
        config_id = create_response["configId"]

        # Delete it
        response = provider.delete_config(
            context=context, config_id=config_id, config_type=ConfigCapabilityType.tracking
        )

        assert response["configId"] == config_id
        assert config_id not in groundstation_stores.configs

    def test_delete_config_in_use_by_mission_profile(self, provider, context):
        """Test that deleting a config used by a mission profile fails."""
        # Create configs
        tracking_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        tracking_response = provider.create_config(
            context=context, name="mp-tracking", config_data=tracking_data
        )
        tracking_arn = tracking_response["configArn"]
        tracking_id = tracking_response["configId"]

        downlink_data = {
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2200.0, "units": "MHz"},
                    "bandwidth": {"value": 125.0, "units": "MHz"},
                }
            }
        }
        downlink_response = provider.create_config(
            context=context, name="mp-downlink", config_data=downlink_data
        )
        downlink_arn = downlink_response["configArn"]

        def_data = {
            "dataflowEndpointConfig": {
                "dataflowEndpointName": "test-endpoint",
                "dataflowEndpointRegion": "us-east-1",
            }
        }
        def_response = provider.create_config(
            context=context, name="mp-dataflow", config_data=def_data
        )
        def_arn = def_response["configArn"]

        # Create mission profile using the tracking config
        provider.create_mission_profile(
            context=context,
            name="test-mission",
            minimum_viable_contact_duration_seconds=60,
            contact_pre_pass_duration_seconds=120,
            contact_post_pass_duration_seconds=60,
            tracking_config_arn=tracking_arn,
            dataflow_edges=[[tracking_arn, downlink_arn], [downlink_arn, def_arn]],
        )

        # Try to delete the tracking config (should fail)
        with pytest.raises(DependencyException) as exc:
            provider.delete_config(
                context=context,
                config_id=tracking_id,
                config_type=ConfigCapabilityType.tracking,
            )

        assert "is used by mission profile" in str(exc.value)


class TestListConfigs:
    """Tests for ListConfigs operation."""

    def test_list_empty_configs(self, provider, context):
        """Test listing when no configs exist."""
        response = provider.list_configs(context=context)

        assert response["configList"] == []

    def test_list_configs(self, provider, context):
        """Test listing multiple configurations."""
        # Create several configs
        tracking_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        provider.create_config(context=context, name="tracking-1", config_data=tracking_data)
        provider.create_config(context=context, name="tracking-2", config_data=tracking_data)

        downlink_data = {
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2200.0, "units": "MHz"},
                    "bandwidth": {"value": 125.0, "units": "MHz"},
                }
            }
        }
        provider.create_config(context=context, name="downlink-1", config_data=downlink_data)

        # List all configs
        response = provider.list_configs(context=context)

        assert len(response["configList"]) == 3
        config_names = [c["name"] for c in response["configList"]]
        assert "tracking-1" in config_names
        assert "tracking-2" in config_names
        assert "downlink-1" in config_names

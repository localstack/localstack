"""Integration tests for mission profile dataflow edge validation.

Tests dataflow edge ordering rules and complete mission scenarios.
"""

from datetime import datetime, timedelta

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers


@markers.aws.validated
class TestDataflowEdgeValidation:
    """Test dataflow edge validation rules."""

    def test_valid_dataflow_edge_sequence(self, aws_client):
        """Test valid dataflow edge sequence: tracking -> downlink -> dataflow."""
        # Create configs in valid order
        tracking = aws_client.groundstation.create_config(
            name="edge-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        downlink = aws_client.groundstation.create_config(
            name="edge-downlink",
            configData={
                "antennaDownlinkConfig": {
                    "spectrumConfig": {
                        "centerFrequency": {"value": 2200.0, "units": "MHz"},
                        "bandwidth": {"value": 125.0, "units": "MHz"},
                    }
                }
            },
        )
        dataflow = aws_client.groundstation.create_config(
            name="edge-dataflow",
            configData={
                "dataflowEndpointConfig": {
                    "dataflowEndpointName": "test-endpoint",
                    "dataflowEndpointRegion": "us-east-1",
                }
            },
        )

        # Create mission profile with valid edges
        mp_response = aws_client.groundstation.create_mission_profile(
            name="valid-edge-mp",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[
                [tracking["configArn"], downlink["configArn"]],
                [downlink["configArn"], dataflow["configArn"]],
            ],
            trackingConfigArn=tracking["configArn"],
        )

        assert "missionProfileId" in mp_response

    def test_invalid_dataflow_edge_wrong_order(self, aws_client):
        """Test invalid dataflow edge: dataflow before downlink."""
        tracking = aws_client.groundstation.create_config(
            name="invalid-order-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        downlink = aws_client.groundstation.create_config(
            name="invalid-order-downlink",
            configData={
                "antennaDownlinkConfig": {
                    "spectrumConfig": {
                        "centerFrequency": {"value": 2200.0, "units": "MHz"},
                        "bandwidth": {"value": 125.0, "units": "MHz"},
                    }
                }
            },
        )
        dataflow = aws_client.groundstation.create_config(
            name="invalid-order-dataflow",
            configData={
                "dataflowEndpointConfig": {
                    "dataflowEndpointName": "test-endpoint",
                    "dataflowEndpointRegion": "us-east-1",
                }
            },
        )

        # Invalid: dataflow comes before downlink
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_mission_profile(
                name="invalid-order-mp",
                contactPrePassDurationSeconds=120,
                contactPostPassDurationSeconds=120,
                minimumViableContactDurationSeconds=60,
                dataflowEdges=[
                    [tracking["configArn"], dataflow["configArn"]],
                    [dataflow["configArn"], downlink["configArn"]],
                ],
                trackingConfigArn=tracking["configArn"],
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_dataflow_edge_with_demod_decode(self, aws_client):
        """Test dataflow edge with demod/decode config."""
        tracking = aws_client.groundstation.create_config(
            name="demod-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        demod_decode = aws_client.groundstation.create_config(
            name="demod-decode-config",
            configData={
                "antennaDownlinkDemodDecodeConfig": {
                    "spectrumConfig": {
                        "centerFrequency": {"value": 2200.0, "units": "MHz"},
                        "bandwidth": {"value": 125.0, "units": "MHz"},
                    },
                    "demodulationConfig": {"unvalidatedJSON": '{"type": "QPSK"}'},
                    "decodeConfig": {"unvalidatedJSON": '{"type": "Turbo"}'},
                }
            },
        )
        dataflow = aws_client.groundstation.create_config(
            name="demod-dataflow",
            configData={
                "dataflowEndpointConfig": {
                    "dataflowEndpointName": "test-endpoint",
                    "dataflowEndpointRegion": "us-east-1",
                }
            },
        )

        # Valid: tracking -> demod/decode -> dataflow
        mp_response = aws_client.groundstation.create_mission_profile(
            name="demod-mp",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[
                [tracking["configArn"], demod_decode["configArn"]],
                [demod_decode["configArn"], dataflow["configArn"]],
            ],
            trackingConfigArn=tracking["configArn"],
        )

        assert "missionProfileId" in mp_response

    def test_uplink_downlink_dataflow_edge(self, aws_client):
        """Test uplink -> downlink -> dataflow edge sequence."""
        tracking = aws_client.groundstation.create_config(
            name="updown-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        uplink = aws_client.groundstation.create_config(
            name="updown-uplink",
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
        downlink = aws_client.groundstation.create_config(
            name="updown-downlink",
            configData={
                "antennaDownlinkConfig": {
                    "spectrumConfig": {
                        "centerFrequency": {"value": 2200.0, "units": "MHz"},
                        "bandwidth": {"value": 125.0, "units": "MHz"},
                    }
                }
            },
        )
        dataflow = aws_client.groundstation.create_config(
            name="updown-dataflow",
            configData={
                "dataflowEndpointConfig": {
                    "dataflowEndpointName": "test-endpoint",
                    "dataflowEndpointRegion": "us-east-1",
                }
            },
        )

        # Valid: tracking -> uplink -> downlink -> dataflow
        mp_response = aws_client.groundstation.create_mission_profile(
            name="updown-mp",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[
                [tracking["configArn"], uplink["configArn"]],
                [uplink["configArn"], downlink["configArn"]],
                [downlink["configArn"], dataflow["configArn"]],
            ],
            trackingConfigArn=tracking["configArn"],
        )

        assert "missionProfileId" in mp_response

    def test_dataflow_edge_with_duplicate_configs(self, aws_client):
        """Test dataflow edge validation rejects duplicate configs."""
        tracking = aws_client.groundstation.create_config(
            name="dup-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )

        # Invalid: same config used twice in sequence
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_mission_profile(
                name="dup-mp",
                contactPrePassDurationSeconds=120,
                contactPostPassDurationSeconds=120,
                minimumViableContactDurationSeconds=60,
                dataflowEdges=[
                    [tracking["configArn"], tracking["configArn"]],
                ],
                trackingConfigArn=tracking["configArn"],
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_dataflow_edge_with_nonexistent_config(self, aws_client):
        """Test dataflow edge validation rejects non-existent configs."""
        tracking = aws_client.groundstation.create_config(
            name="ne-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )

        invalid_arn = "arn:aws:groundstation:us-east-1:123456789012:config/antenna-downlink/00000000-0000-0000-0000-000000000000"

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_mission_profile(
                name="ne-mp",
                contactPrePassDurationSeconds=120,
                contactPostPassDurationSeconds=120,
                minimumViableContactDurationSeconds=60,
                dataflowEdges=[
                    [tracking["configArn"], invalid_arn],
                ],
                trackingConfigArn=tracking["configArn"],
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"


@markers.aws.validated
class TestMissionProfileScenarios:
    """Test complete mission profile scenarios."""

    def test_downlink_only_mission(self, aws_client):
        """Test complete downlink-only mission profile."""
        # Create all required configs
        tracking = aws_client.groundstation.create_config(
            name="dl-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
            tags={"Mission": "Downlink"},
        )
        downlink = aws_client.groundstation.create_config(
            name="dl-antenna",
            configData={
                "antennaDownlinkConfig": {
                    "spectrumConfig": {
                        "centerFrequency": {"value": 2200.0, "units": "MHz"},
                        "bandwidth": {"value": 125.0, "units": "MHz"},
                    }
                }
            },
            tags={"Mission": "Downlink"},
        )
        dataflow = aws_client.groundstation.create_config(
            name="dl-dataflow",
            configData={
                "dataflowEndpointConfig": {
                    "dataflowEndpointName": "downlink-endpoint",
                    "dataflowEndpointRegion": "us-east-1",
                }
            },
            tags={"Mission": "Downlink"},
        )

        # Create mission profile
        mp_response = aws_client.groundstation.create_mission_profile(
            name="downlink-mission",
            contactPrePassDurationSeconds=180,
            contactPostPassDurationSeconds=180,
            minimumViableContactDurationSeconds=120,
            dataflowEdges=[
                [tracking["configArn"], downlink["configArn"]],
                [downlink["configArn"], dataflow["configArn"]],
            ],
            trackingConfigArn=tracking["configArn"],
            tags={"Mission": "Downlink", "Type": "Data-Reception"},
        )

        # Verify mission profile
        mp = aws_client.groundstation.get_mission_profile(
            missionProfileId=mp_response["missionProfileId"]
        )
        assert mp["name"] == "downlink-mission"
        assert len(mp["dataflowEdges"]) == 2

        # Reserve contact with this mission profile
        start_time = datetime.utcnow() + timedelta(hours=1)
        end_time = start_time + timedelta(minutes=15)

        contact_response = aws_client.groundstation.reserve_contact(
            missionProfileArn=mp_response["missionProfileArn"],
            satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/25544",
            startTime=start_time,
            endTime=end_time,
            groundStation="Ohio Ground Station",
        )

        assert "contactId" in contact_response

    def test_uplink_only_mission(self, aws_client):
        """Test complete uplink-only mission profile."""
        tracking = aws_client.groundstation.create_config(
            name="ul-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        uplink = aws_client.groundstation.create_config(
            name="ul-antenna",
            configData={
                "antennaUplinkConfig": {
                    "spectrumConfig": {
                        "centerFrequency": {"value": 2025.0, "units": "MHz"},
                        "polarization": "LEFT_HAND",
                    },
                    "targetEirp": {"value": 25.0, "units": "dBW"},
                }
            },
        )
        dataflow = aws_client.groundstation.create_config(
            name="ul-dataflow",
            configData={
                "dataflowEndpointConfig": {
                    "dataflowEndpointName": "uplink-endpoint",
                    "dataflowEndpointRegion": "us-east-1",
                }
            },
        )

        # Create uplink mission
        mp_response = aws_client.groundstation.create_mission_profile(
            name="uplink-mission",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=90,
            dataflowEdges=[
                [tracking["configArn"], uplink["configArn"]],
                [uplink["configArn"], dataflow["configArn"]],
            ],
            trackingConfigArn=tracking["configArn"],
        )

        assert "missionProfileId" in mp_response

    def test_bidirectional_mission(self, aws_client):
        """Test bidirectional (uplink + downlink) mission profile."""
        tracking = aws_client.groundstation.create_config(
            name="bidir-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        uplink = aws_client.groundstation.create_config(
            name="bidir-uplink",
            configData={
                "antennaUplinkConfig": {
                    "spectrumConfig": {
                        "centerFrequency": {"value": 2025.0, "units": "MHz"},
                        "polarization": "RIGHT_HAND",
                    },
                    "targetEirp": {"value": 22.0, "units": "dBW"},
                }
            },
        )
        downlink = aws_client.groundstation.create_config(
            name="bidir-downlink",
            configData={
                "antennaDownlinkConfig": {
                    "spectrumConfig": {
                        "centerFrequency": {"value": 2200.0, "units": "MHz"},
                        "bandwidth": {"value": 125.0, "units": "MHz"},
                    }
                }
            },
        )
        dataflow_up = aws_client.groundstation.create_config(
            name="bidir-dataflow-up",
            configData={
                "dataflowEndpointConfig": {
                    "dataflowEndpointName": "uplink-endpoint",
                    "dataflowEndpointRegion": "us-east-1",
                }
            },
        )
        dataflow_down = aws_client.groundstation.create_config(
            name="bidir-dataflow-down",
            configData={
                "dataflowEndpointConfig": {
                    "dataflowEndpointName": "downlink-endpoint",
                    "dataflowEndpointRegion": "us-east-1",
                }
            },
        )

        # Bidirectional mission with both uplink and downlink paths
        mp_response = aws_client.groundstation.create_mission_profile(
            name="bidirectional-mission",
            contactPrePassDurationSeconds=180,
            contactPostPassDurationSeconds=180,
            minimumViableContactDurationSeconds=120,
            dataflowEdges=[
                # Uplink path
                [tracking["configArn"], uplink["configArn"]],
                [uplink["configArn"], dataflow_up["configArn"]],
                # Downlink path
                [tracking["configArn"], downlink["configArn"]],
                [downlink["configArn"], dataflow_down["configArn"]],
            ],
            trackingConfigArn=tracking["configArn"],
        )

        assert "missionProfileId" in mp_response

        # Verify edges
        mp = aws_client.groundstation.get_mission_profile(
            missionProfileId=mp_response["missionProfileId"]
        )
        assert len(mp["dataflowEdges"]) == 4


@markers.aws.validated
class TestMissionProfileUpdates:
    """Test mission profile update scenarios."""

    def test_update_dataflow_edges(self, aws_client):
        """Test updating dataflow edges in existing mission profile."""
        # Create initial configs
        tracking = aws_client.groundstation.create_config(
            name="update-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        downlink1 = aws_client.groundstation.create_config(
            name="update-downlink1",
            configData={
                "antennaDownlinkConfig": {
                    "spectrumConfig": {
                        "centerFrequency": {"value": 2200.0, "units": "MHz"},
                        "bandwidth": {"value": 125.0, "units": "MHz"},
                    }
                }
            },
        )
        dataflow = aws_client.groundstation.create_config(
            name="update-dataflow",
            configData={
                "dataflowEndpointConfig": {
                    "dataflowEndpointName": "test-endpoint",
                    "dataflowEndpointRegion": "us-east-1",
                }
            },
        )

        # Create mission profile
        mp_response = aws_client.groundstation.create_mission_profile(
            name="update-edges-mp",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[
                [tracking["configArn"], downlink1["configArn"]],
                [downlink1["configArn"], dataflow["configArn"]],
            ],
            trackingConfigArn=tracking["configArn"],
        )
        mp_id = mp_response["missionProfileId"]

        # Create new downlink config
        downlink2 = aws_client.groundstation.create_config(
            name="update-downlink2",
            configData={
                "antennaDownlinkConfig": {
                    "spectrumConfig": {
                        "centerFrequency": {"value": 2250.0, "units": "MHz"},
                        "bandwidth": {"value": 150.0, "units": "MHz"},
                    }
                }
            },
        )

        # Update dataflow edges
        aws_client.groundstation.update_mission_profile(
            missionProfileId=mp_id,
            dataflowEdges=[
                [tracking["configArn"], downlink2["configArn"]],
                [downlink2["configArn"], dataflow["configArn"]],
            ],
        )

        # Verify update
        mp = aws_client.groundstation.get_mission_profile(missionProfileId=mp_id)
        assert downlink2["configArn"] in str(mp["dataflowEdges"])
        assert downlink1["configArn"] not in str(mp["dataflowEdges"])

    def test_update_contact_durations(self, aws_client):
        """Test updating pre/post pass durations."""
        tracking = aws_client.groundstation.create_config(
            name="duration-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )

        mp_response = aws_client.groundstation.create_mission_profile(
            name="duration-mp",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking["configArn"],
        )
        mp_id = mp_response["missionProfileId"]

        # Update durations
        aws_client.groundstation.update_mission_profile(
            missionProfileId=mp_id,
            contactPrePassDurationSeconds=300,
            contactPostPassDurationSeconds=300,
            minimumViableContactDurationSeconds=120,
        )

        # Verify update
        mp = aws_client.groundstation.get_mission_profile(missionProfileId=mp_id)
        assert mp["contactPrePassDurationSeconds"] == 300
        assert mp["contactPostPassDurationSeconds"] == 300
        assert mp["minimumViableContactDurationSeconds"] == 120

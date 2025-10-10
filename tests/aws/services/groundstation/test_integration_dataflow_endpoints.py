"""Integration tests for dataflow endpoint group integration scenarios.

Tests endpoint groups with mission profiles and complete data flow scenarios.
"""

from datetime import datetime, timedelta

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers


@markers.aws.validated
class TestDataflowEndpointIntegration:
    """Test dataflow endpoint group integration with configs and mission profiles."""

    def test_dataflow_endpoint_group_in_mission_profile(self, aws_client):
        """Test using dataflow endpoint group in a mission profile."""
        # Create dataflow endpoint group
        endpoint_details = [
            {
                "endpoint": {
                    "address": {"name": "10.0.1.100", "port": 50000},
                    "name": "mission-endpoint",
                },
                "securityDetails": {
                    "roleArn": "arn:aws:iam::123456789012:role/GroundStationRole",
                    "securityGroupIds": ["sg-12345678"],
                    "subnetIds": ["subnet-12345678"],
                },
            }
        ]

        deg_response = aws_client.groundstation.create_dataflow_endpoint_group(
            endpointDetails=endpoint_details
        )

        # Create configs
        tracking = aws_client.groundstation.create_config(
            name="deg-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        downlink = aws_client.groundstation.create_config(
            name="deg-downlink",
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
            name="deg-dataflow",
            configData={
                "dataflowEndpointConfig": {
                    "dataflowEndpointName": "mission-endpoint",
                    "dataflowEndpointRegion": "us-east-1",
                }
            },
        )

        # Create mission profile using the endpoint group
        mp_response = aws_client.groundstation.create_mission_profile(
            name="deg-mission",
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

    def test_multiple_endpoints_in_group(self, aws_client):
        """Test dataflow endpoint group with multiple endpoints (primary/backup)."""
        endpoint_details = [
            {
                "endpoint": {
                    "address": {"name": "10.0.1.100", "port": 50000},
                    "name": "primary-endpoint",
                },
                "securityDetails": {
                    "roleArn": "arn:aws:iam::123456789012:role/GroundStationRole",
                    "securityGroupIds": ["sg-primary"],
                    "subnetIds": ["subnet-primary"],
                },
            },
            {
                "endpoint": {
                    "address": {"name": "10.0.1.101", "port": 50001},
                    "name": "backup-endpoint",
                },
                "securityDetails": {
                    "roleArn": "arn:aws:iam::123456789012:role/GroundStationRole",
                    "securityGroupIds": ["sg-backup"],
                    "subnetIds": ["subnet-backup"],
                },
            },
        ]

        deg_response = aws_client.groundstation.create_dataflow_endpoint_group(
            endpointDetails=endpoint_details,
            tags={"Type": "Redundant", "Priority": "High"},
        )

        # Verify both endpoints are stored
        deg = aws_client.groundstation.get_dataflow_endpoint_group(
            dataflowEndpointGroupId=deg_response["dataflowEndpointGroupId"]
        )

        assert len(deg["endpointsDetails"]) == 2
        endpoint_names = [e["endpoint"]["name"] for e in deg["endpointsDetails"]]
        assert "primary-endpoint" in endpoint_names
        assert "backup-endpoint" in endpoint_names

    def test_dataflow_endpoint_group_deletion_with_active_mission(self, aws_client):
        """Test that endpoint group in use cannot be deleted."""
        # Create endpoint group
        endpoint_details = [
            {
                "endpoint": {
                    "address": {"name": "10.0.1.100", "port": 50000},
                    "name": "active-endpoint",
                }
            }
        ]

        deg_response = aws_client.groundstation.create_dataflow_endpoint_group(
            endpointDetails=endpoint_details
        )

        # Create configs
        tracking = aws_client.groundstation.create_config(
            name="active-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        dataflow = aws_client.groundstation.create_config(
            name="active-dataflow",
            configData={
                "dataflowEndpointConfig": {
                    "dataflowEndpointName": "active-endpoint",
                    "dataflowEndpointRegion": "us-east-1",
                }
            },
        )

        # Create mission profile
        mp_response = aws_client.groundstation.create_mission_profile(
            name="active-mission",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[[tracking["configArn"], dataflow["configArn"]]],
            trackingConfigArn=tracking["configArn"],
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

        # Try to delete endpoint group (should fail - in use)
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.delete_dataflow_endpoint_group(
                dataflowEndpointGroupId=deg_response["dataflowEndpointGroupId"]
            )
        assert exc.value.response["Error"]["Code"] == "DependencyException"


@markers.aws.validated
class TestEndpointNetworkConfiguration:
    """Test endpoint network configuration validation."""

    def test_endpoint_with_security_details(self, aws_client):
        """Test creating endpoint with full security details."""
        endpoint_details = [
            {
                "endpoint": {
                    "address": {"name": "10.0.1.100", "port": 50000},
                    "name": "secure-endpoint",
                },
                "securityDetails": {
                    "roleArn": "arn:aws:iam::123456789012:role/GroundStationRole",
                    "securityGroupIds": ["sg-12345678", "sg-87654321"],
                    "subnetIds": ["subnet-12345678", "subnet-87654321"],
                },
            }
        ]

        response = aws_client.groundstation.create_dataflow_endpoint_group(
            endpointDetails=endpoint_details
        )

        # Verify security details are stored
        deg = aws_client.groundstation.get_dataflow_endpoint_group(
            dataflowEndpointGroupId=response["dataflowEndpointGroupId"]
        )

        security_details = deg["endpointsDetails"][0]["securityDetails"]
        assert security_details["roleArn"] == "arn:aws:iam::123456789012:role/GroundStationRole"
        assert len(security_details["securityGroupIds"]) == 2
        assert len(security_details["subnetIds"]) == 2

    def test_endpoint_without_security_details(self, aws_client):
        """Test creating endpoint without security details (optional)."""
        endpoint_details = [
            {
                "endpoint": {
                    "address": {"name": "10.0.1.100", "port": 50000},
                    "name": "simple-endpoint",
                }
            }
        ]

        response = aws_client.groundstation.create_dataflow_endpoint_group(
            endpointDetails=endpoint_details
        )

        assert "dataflowEndpointGroupId" in response

    def test_endpoint_invalid_port_number(self, aws_client):
        """Test endpoint with invalid port number."""
        # Port too low
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_dataflow_endpoint_group(
                endpointDetails=[
                    {
                        "endpoint": {
                            "address": {"name": "10.0.1.100", "port": 0},
                            "name": "invalid-port-low",
                        }
                    }
                ]
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

        # Port too high
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_dataflow_endpoint_group(
                endpointDetails=[
                    {
                        "endpoint": {
                            "address": {"name": "10.0.1.100", "port": 99999},
                            "name": "invalid-port-high",
                        }
                    }
                ]
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"

    def test_endpoint_invalid_ip_address(self, aws_client):
        """Test endpoint with invalid IP address format."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_dataflow_endpoint_group(
                endpointDetails=[
                    {
                        "endpoint": {
                            "address": {"name": "invalid.ip.address", "port": 50000},
                            "name": "invalid-ip",
                        }
                    }
                ]
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"


@markers.aws.validated
class TestEndpointGroupLifecycle:
    """Test complete endpoint group lifecycle scenarios."""

    def test_endpoint_group_create_tag_delete(self, aws_client):
        """Test complete lifecycle: create -> tag -> delete."""
        # Create
        endpoint_details = [
            {
                "endpoint": {
                    "address": {"name": "10.0.1.100", "port": 50000},
                    "name": "lifecycle-endpoint",
                }
            }
        ]

        create_response = aws_client.groundstation.create_dataflow_endpoint_group(
            endpointDetails=endpoint_details, tags={"Stage": "Created"}
        )
        deg_id = create_response["dataflowEndpointGroupId"]
        deg_arn = create_response["dataflowEndpointGroupArn"]

        # Verify created
        deg = aws_client.groundstation.get_dataflow_endpoint_group(dataflowEndpointGroupId=deg_id)
        assert deg["dataflowEndpointGroupId"] == deg_id

        # Add more tags
        aws_client.groundstation.tag_resource(
            resourceArn=deg_arn, tags={"Stage": "Active", "Owner": "TeamB"}
        )

        # Verify tags
        tags = aws_client.groundstation.list_tags_for_resource(resourceArn=deg_arn)
        assert tags["tags"]["Stage"] == "Active"
        assert tags["tags"]["Owner"] == "TeamB"

        # Delete
        aws_client.groundstation.delete_dataflow_endpoint_group(dataflowEndpointGroupId=deg_id)

        # Verify deleted
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.get_dataflow_endpoint_group(dataflowEndpointGroupId=deg_id)
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"

    def test_list_endpoint_groups_with_filters(self, aws_client):
        """Test listing endpoint groups."""
        # Create multiple endpoint groups
        for i in range(3):
            aws_client.groundstation.create_dataflow_endpoint_group(
                endpointDetails=[
                    {
                        "endpoint": {
                            "address": {"name": f"10.0.1.{100 + i}", "port": 50000 + i},
                            "name": f"list-endpoint-{i}",
                        }
                    }
                ],
                tags={"Batch": "List-Test"},
            )

        # List all
        list_response = aws_client.groundstation.list_dataflow_endpoint_groups()

        # Verify structure
        assert "dataflowEndpointGroupList" in list_response
        assert len(list_response["dataflowEndpointGroupList"]) >= 3

        for deg in list_response["dataflowEndpointGroupList"]:
            assert "dataflowEndpointGroupId" in deg
            assert "dataflowEndpointGroupArn" in deg


@markers.aws.validated
class TestEndToEndDataFlow:
    """Test complete end-to-end data flow scenarios."""

    def test_complete_data_reception_flow(self, aws_client):
        """Test complete data reception flow: satellite -> antenna -> endpoint."""
        # Step 1: Create dataflow endpoint group
        endpoint_details = [
            {
                "endpoint": {
                    "address": {"name": "10.0.1.100", "port": 50000},
                    "name": "data-reception-endpoint",
                },
                "securityDetails": {
                    "roleArn": "arn:aws:iam::123456789012:role/GroundStationRole",
                    "securityGroupIds": ["sg-reception"],
                    "subnetIds": ["subnet-reception"],
                },
            }
        ]

        deg_response = aws_client.groundstation.create_dataflow_endpoint_group(
            endpointDetails=endpoint_details, tags={"Flow": "Reception"}
        )

        # Step 2: Create tracking config
        tracking = aws_client.groundstation.create_config(
            name="reception-tracking",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
            tags={"Flow": "Reception"},
        )

        # Step 3: Create downlink config with demod/decode
        downlink = aws_client.groundstation.create_config(
            name="reception-downlink",
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
            tags={"Flow": "Reception"},
        )

        # Step 4: Create dataflow endpoint config
        dataflow = aws_client.groundstation.create_config(
            name="reception-dataflow",
            configData={
                "dataflowEndpointConfig": {
                    "dataflowEndpointName": "data-reception-endpoint",
                    "dataflowEndpointRegion": "us-east-1",
                }
            },
            tags={"Flow": "Reception"},
        )

        # Step 5: Create mission profile
        mp_response = aws_client.groundstation.create_mission_profile(
            name="data-reception-mission",
            contactPrePassDurationSeconds=180,
            contactPostPassDurationSeconds=180,
            minimumViableContactDurationSeconds=120,
            dataflowEdges=[
                [tracking["configArn"], downlink["configArn"]],
                [downlink["configArn"], dataflow["configArn"]],
            ],
            trackingConfigArn=tracking["configArn"],
            tags={"Flow": "Reception"},
        )

        # Step 6: Reserve contact
        start_time = datetime.utcnow() + timedelta(hours=1)
        end_time = start_time + timedelta(minutes=15)

        contact_response = aws_client.groundstation.reserve_contact(
            missionProfileArn=mp_response["missionProfileArn"],
            satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/25544",
            startTime=start_time,
            endTime=end_time,
            groundStation="Ohio Ground Station",
            tags={"Flow": "Reception"},
        )

        # Step 7: Verify complete flow
        contact = aws_client.groundstation.describe_contact(contactId=contact_response["contactId"])
        assert contact["missionProfileArn"] == mp_response["missionProfileArn"]
        assert contact["satelliteArn"].endswith("satellite/25544")
        assert contact["groundStation"] == "Ohio Ground Station"

        # Verify minute usage includes this contact
        now = datetime.utcnow()
        usage = aws_client.groundstation.get_minute_usage(month=now.month, year=now.year)
        assert usage["totalScheduledMinutes"] >= 15  # At least the contact duration

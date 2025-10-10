"""Integration tests for Ground Station Dataflow Endpoint Group operations.

Tests CRUD operations for dataflow endpoint groups.
"""

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers


@markers.aws.validated
class TestDataflowEndpointGroupCreate:
    """Test CreateDataflowEndpointGroup operation."""

    def test_create_dataflow_endpoint_group(self, aws_client):
        """Test creating a dataflow endpoint group."""
        endpoint_details = [
            {
                "endpoint": {
                    "address": {"name": "10.0.1.100", "port": 50000},
                    "name": "primary-endpoint",
                },
                "securityDetails": {
                    "roleArn": "arn:aws:iam::123456789012:role/GroundStationRole",
                    "securityGroupIds": ["sg-12345678"],
                    "subnetIds": ["subnet-12345678"],
                },
            }
        ]

        response = aws_client.groundstation.create_dataflow_endpoint_group(
            endpointDetails=endpoint_details
        )

        assert "dataflowEndpointGroupId" in response
        assert "dataflowEndpointGroupArn" in response
        assert "arn:aws:groundstation" in response["dataflowEndpointGroupArn"]

    def test_create_dataflow_endpoint_group_with_tags(self, aws_client):
        """Test creating a dataflow endpoint group with tags."""
        endpoint_details = [
            {
                "endpoint": {
                    "address": {"name": "10.0.1.100", "port": 50000},
                    "name": "endpoint-with-tags",
                }
            }
        ]

        response = aws_client.groundstation.create_dataflow_endpoint_group(
            endpointDetails=endpoint_details,
            tags={"Environment": "Production", "Team": "Satellite"},
        )

        assert "dataflowEndpointGroupId" in response
        deg_arn = response["dataflowEndpointGroupArn"]

        # Verify tags
        tags_response = aws_client.groundstation.list_tags_for_resource(resourceArn=deg_arn)
        assert tags_response["tags"]["Environment"] == "Production"
        assert tags_response["tags"]["Team"] == "Satellite"

    def test_create_dataflow_endpoint_group_multiple_endpoints(self, aws_client):
        """Test creating a dataflow endpoint group with multiple endpoints."""
        endpoint_details = [
            {
                "endpoint": {
                    "address": {"name": "10.0.1.100", "port": 50000},
                    "name": "primary",
                }
            },
            {
                "endpoint": {
                    "address": {"name": "10.0.1.101", "port": 50001},
                    "name": "secondary",
                }
            },
        ]

        response = aws_client.groundstation.create_dataflow_endpoint_group(
            endpointDetails=endpoint_details
        )

        assert "dataflowEndpointGroupId" in response

        # Verify both endpoints are present
        deg_id = response["dataflowEndpointGroupId"]
        get_response = aws_client.groundstation.get_dataflow_endpoint_group(
            dataflowEndpointGroupId=deg_id
        )

        assert len(get_response["endpointsDetails"]) == 2

    def test_create_dataflow_endpoint_group_invalid_port(self, aws_client):
        """Test creating dataflow endpoint group with invalid port."""
        endpoint_details = [
            {
                "endpoint": {
                    "address": {"name": "10.0.1.100", "port": 99999},  # Invalid port
                    "name": "invalid-port",
                }
            }
        ]

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.create_dataflow_endpoint_group(
                endpointDetails=endpoint_details
            )
        assert exc.value.response["Error"]["Code"] == "InvalidParameterException"


@markers.aws.validated
class TestDataflowEndpointGroupGet:
    """Test GetDataflowEndpointGroup operation."""

    def test_get_dataflow_endpoint_group(self, aws_client):
        """Test retrieving a dataflow endpoint group."""
        endpoint_details = [
            {
                "endpoint": {
                    "address": {"name": "10.0.1.100", "port": 50000},
                    "name": "get-test-endpoint",
                }
            }
        ]

        create_response = aws_client.groundstation.create_dataflow_endpoint_group(
            endpointDetails=endpoint_details
        )
        deg_id = create_response["dataflowEndpointGroupId"]

        # Get dataflow endpoint group
        get_response = aws_client.groundstation.get_dataflow_endpoint_group(
            dataflowEndpointGroupId=deg_id
        )

        assert get_response["dataflowEndpointGroupId"] == deg_id
        assert "dataflowEndpointGroupArn" in get_response
        assert "endpointsDetails" in get_response
        assert len(get_response["endpointsDetails"]) == 1
        assert get_response["endpointsDetails"][0]["endpoint"]["name"] == "get-test-endpoint"

    def test_get_dataflow_endpoint_group_not_found(self, aws_client):
        """Test getting a non-existent dataflow endpoint group."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.get_dataflow_endpoint_group(
                dataflowEndpointGroupId="00000000-0000-0000-0000-000000000000"
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"


@markers.aws.validated
class TestDataflowEndpointGroupDelete:
    """Test DeleteDataflowEndpointGroup operation."""

    def test_delete_dataflow_endpoint_group(self, aws_client):
        """Test deleting a dataflow endpoint group."""
        endpoint_details = [
            {
                "endpoint": {
                    "address": {"name": "10.0.1.100", "port": 50000},
                    "name": "delete-test",
                }
            }
        ]

        create_response = aws_client.groundstation.create_dataflow_endpoint_group(
            endpointDetails=endpoint_details
        )
        deg_id = create_response["dataflowEndpointGroupId"]

        # Delete dataflow endpoint group
        delete_response = aws_client.groundstation.delete_dataflow_endpoint_group(
            dataflowEndpointGroupId=deg_id
        )

        assert delete_response["dataflowEndpointGroupId"] == deg_id

        # Verify deletion
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.get_dataflow_endpoint_group(dataflowEndpointGroupId=deg_id)
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"

    def test_delete_dataflow_endpoint_group_not_found(self, aws_client):
        """Test deleting a non-existent dataflow endpoint group."""
        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.delete_dataflow_endpoint_group(
                dataflowEndpointGroupId="00000000-0000-0000-0000-000000000000"
            )
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"


@markers.aws.validated
class TestDataflowEndpointGroupList:
    """Test ListDataflowEndpointGroups operation."""

    def test_list_dataflow_endpoint_groups(self, aws_client):
        """Test listing dataflow endpoint groups."""
        endpoint_details = [
            {
                "endpoint": {
                    "address": {"name": "10.0.1.100", "port": 50000},
                    "name": "list-test-1",
                }
            }
        ]

        deg1 = aws_client.groundstation.create_dataflow_endpoint_group(
            endpointDetails=endpoint_details
        )
        deg2 = aws_client.groundstation.create_dataflow_endpoint_group(
            endpointDetails=endpoint_details
        )

        # List dataflow endpoint groups
        list_response = aws_client.groundstation.list_dataflow_endpoint_groups()

        deg_ids = [
            deg["dataflowEndpointGroupId"] for deg in list_response["dataflowEndpointGroupList"]
        ]
        assert deg1["dataflowEndpointGroupId"] in deg_ids
        assert deg2["dataflowEndpointGroupId"] in deg_ids

        # Verify structure
        for deg in list_response["dataflowEndpointGroupList"]:
            assert "dataflowEndpointGroupId" in deg
            assert "dataflowEndpointGroupArn" in deg

    def test_list_dataflow_endpoint_groups_pagination(self, aws_client):
        """Test listing dataflow endpoint groups with pagination."""
        endpoint_details = [
            {
                "endpoint": {
                    "address": {"name": "10.0.1.100", "port": 50000},
                    "name": "pagination-test",
                }
            }
        ]

        for i in range(3):
            aws_client.groundstation.create_dataflow_endpoint_group(
                endpointDetails=endpoint_details
            )

        # List with max results
        list_response = aws_client.groundstation.list_dataflow_endpoint_groups(maxResults=2)

        assert len(list_response["dataflowEndpointGroupList"]) <= 2
        if "nextToken" in list_response:
            next_response = aws_client.groundstation.list_dataflow_endpoint_groups(
                maxResults=2, nextToken=list_response["nextToken"]
            )
            assert "dataflowEndpointGroupList" in next_response

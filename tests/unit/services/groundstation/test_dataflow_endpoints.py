"""Unit tests for Ground Station dataflow endpoint group operations."""

import pytest

from localstack.aws.api import RequestContext
from localstack.aws.api.groundstation import ResourceNotFoundException
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


class TestCreateDataflowEndpointGroup:
    """Tests for CreateDataflowEndpointGroup operation."""

    def test_create_basic_endpoint_group(self, provider, context):
        """Test creating a basic dataflow endpoint group."""
        endpoint_details = [
            {
                "endpoint": {
                    "name": "test-endpoint",
                    "address": {"name": "10.0.0.1", "port": 55888},
                    "mtu": 1500,
                }
            }
        ]

        response = provider.create_dataflow_endpoint_group(
            context=context, endpoint_details=endpoint_details
        )

        assert "dataflowEndpointGroupId" in response
        assert "dataflowEndpointGroupArn" in response
        assert response["dataflowEndpointGroupArn"].startswith(
            "arn:aws:groundstation:us-east-1:000000000000:dataflow-endpoint-group/"
        )

    def test_create_endpoint_group_with_multiple_endpoints(self, provider, context):
        """Test creating an endpoint group with multiple endpoints."""
        endpoint_details = [
            {
                "endpoint": {
                    "name": "endpoint-1",
                    "address": {"name": "10.0.0.1", "port": 55888},
                    "mtu": 1500,
                }
            },
            {
                "endpoint": {
                    "name": "endpoint-2",
                    "address": {"name": "10.0.0.2", "port": 55889},
                    "mtu": 1500,
                }
            },
        ]

        response = provider.create_dataflow_endpoint_group(
            context=context, endpoint_details=endpoint_details
        )

        assert "dataflowEndpointGroupId" in response

        # Verify we can retrieve it
        deg_id = response["dataflowEndpointGroupId"]
        get_response = provider.get_dataflow_endpoint_group(
            context=context, dataflow_endpoint_group_id=deg_id
        )

        assert len(get_response["endpointsDetails"]) == 2

    def test_create_endpoint_group_with_tags(self, provider, context):
        """Test creating an endpoint group with tags."""
        endpoint_details = [
            {
                "endpoint": {
                    "name": "test-endpoint",
                    "address": {"name": "10.0.0.1", "port": 55888},
                    "mtu": 1500,
                }
            }
        ]
        tags = {"Environment": "production", "Team": "satellite-ops"}

        response = provider.create_dataflow_endpoint_group(
            context=context, endpoint_details=endpoint_details, tags=tags
        )

        deg_arn = response["dataflowEndpointGroupArn"]
        assert deg_arn in groundstation_stores.tags
        assert groundstation_stores.tags[deg_arn] == tags


class TestGetDataflowEndpointGroup:
    """Tests for GetDataflowEndpointGroup operation."""

    def test_get_existing_endpoint_group(self, provider, context):
        """Test getting an existing dataflow endpoint group."""
        # Create an endpoint group
        endpoint_details = [
            {
                "endpoint": {
                    "name": "test-endpoint",
                    "address": {"name": "192.168.1.100", "port": 55888},
                    "mtu": 1500,
                }
            }
        ]

        create_response = provider.create_dataflow_endpoint_group(
            context=context, endpoint_details=endpoint_details
        )
        deg_id = create_response["dataflowEndpointGroupId"]

        # Get the endpoint group
        response = provider.get_dataflow_endpoint_group(
            context=context, dataflow_endpoint_group_id=deg_id
        )

        assert response["dataflowEndpointGroupId"] == deg_id
        assert "dataflowEndpointGroupArn" in response
        assert len(response["endpointsDetails"]) == 1
        assert response["endpointsDetails"][0]["endpoint"]["name"] == "test-endpoint"

    def test_get_nonexistent_endpoint_group(self, provider, context):
        """Test getting a non-existent endpoint group."""
        with pytest.raises(ResourceNotFoundException) as exc:
            provider.get_dataflow_endpoint_group(
                context=context, dataflow_endpoint_group_id="nonexistent-id"
            )

        assert "not found" in str(exc.value)


class TestListDataflowEndpointGroups:
    """Tests for ListDataflowEndpointGroups operation."""

    def test_list_empty_endpoint_groups(self, provider, context):
        """Test listing when no endpoint groups exist."""
        response = provider.list_dataflow_endpoint_groups(context=context)

        assert response["dataflowEndpointGroupList"] == []

    def test_list_multiple_endpoint_groups(self, provider, context):
        """Test listing multiple endpoint groups."""
        # Create several endpoint groups
        for i in range(3):
            endpoint_details = [
                {
                    "endpoint": {
                        "name": f"endpoint-{i}",
                        "address": {"name": f"10.0.0.{i}", "port": 55888 + i},
                        "mtu": 1500,
                    }
                }
            ]
            provider.create_dataflow_endpoint_group(
                context=context, endpoint_details=endpoint_details
            )

        # List all endpoint groups
        response = provider.list_dataflow_endpoint_groups(context=context)

        assert len(response["dataflowEndpointGroupList"]) == 3


class TestDeleteDataflowEndpointGroup:
    """Tests for DeleteDataflowEndpointGroup operation."""

    def test_delete_endpoint_group(self, provider, context):
        """Test deleting a dataflow endpoint group."""
        # Create an endpoint group
        endpoint_details = [
            {
                "endpoint": {
                    "name": "test-endpoint",
                    "address": {"name": "10.0.0.1", "port": 55888},
                    "mtu": 1500,
                }
            }
        ]
        create_response = provider.create_dataflow_endpoint_group(
            context=context, endpoint_details=endpoint_details
        )
        deg_id = create_response["dataflowEndpointGroupId"]

        # Delete it
        response = provider.delete_dataflow_endpoint_group(
            context=context, dataflow_endpoint_group_id=deg_id
        )

        assert response["dataflowEndpointGroupId"] == deg_id
        assert deg_id not in groundstation_stores.dataflow_endpoint_groups

    def test_delete_nonexistent_endpoint_group(self, provider, context):
        """Test deleting a non-existent endpoint group."""
        with pytest.raises(ResourceNotFoundException) as exc:
            provider.delete_dataflow_endpoint_group(
                context=context, dataflow_endpoint_group_id="nonexistent-id"
            )

        assert "not found" in str(exc.value)

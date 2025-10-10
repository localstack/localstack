"""Unit tests for Ground Station satellite and ground station operations."""

import pytest

from localstack.aws.api import RequestContext
from localstack.aws.api.groundstation import ResourceNotFoundException
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


class TestListSatellites:
    """Tests for ListSatellites operation."""

    def test_list_satellites(self, provider, context):
        """Test listing satellites returns mock catalog."""
        response = provider.list_satellites(context=context)

        assert "satellites" in response
        assert len(response["satellites"]) == 10  # Mock catalog has 10 satellites

        # Verify structure of first satellite
        satellite = response["satellites"][0]
        assert "satelliteId" in satellite
        assert "satelliteArn" in satellite
        assert "noradSatelliteID" in satellite
        assert "groundStations" in satellite

    def test_satellites_have_uuid_format_ids(self, provider, context):
        """Test that satellite IDs are in UUID format (36 characters)."""
        response = provider.list_satellites(context=context)

        for satellite in response["satellites"]:
            assert len(satellite["satelliteId"]) == 36  # UUID format
            assert satellite["satelliteId"].count("-") == 4  # UUID has 4 hyphens

    def test_satellites_have_valid_norad_ids(self, provider, context):
        """Test that satellites have valid NORAD IDs."""
        response = provider.list_satellites(context=context)

        # Check for known satellites
        norad_ids = [s["noradSatelliteID"] for s in response["satellites"]]
        assert 25544 in norad_ids  # ISS


class TestGetSatellite:
    """Tests for GetSatellite operation."""

    def test_get_iss_satellite(self, provider, context):
        """Test getting the ISS satellite by UUID."""
        # ISS UUID from mock catalog
        iss_id = "11111111-1111-1111-1111-000000025544"

        response = provider.get_satellite(context=context, satellite_id=iss_id)

        assert response["satelliteId"] == iss_id
        assert response["noradSatelliteID"] == 25544
        assert "Ohio Ground Station" in response["groundStations"]

    def test_get_landsat_satellite(self, provider, context):
        """Test getting LANDSAT 8 satellite."""
        landsat_id = "22222222-2222-2222-2222-000000043013"

        response = provider.get_satellite(context=context, satellite_id=landsat_id)

        assert response["satelliteId"] == landsat_id
        assert response["noradSatelliteID"] == 43013

    def test_get_nonexistent_satellite(self, provider, context):
        """Test getting a non-existent satellite."""
        with pytest.raises(ResourceNotFoundException) as exc:
            provider.get_satellite(
                context=context, satellite_id="aaaaaaaa-bbbb-cccc-dddd-999999999999"
            )

        assert "Satellite" in str(exc.value)
        assert "not found" in str(exc.value)


class TestListGroundStations:
    """Tests for ListGroundStations operation."""

    def test_list_ground_stations(self, provider, context):
        """Test listing ground stations returns mock catalog."""
        response = provider.list_ground_stations(context=context)

        assert "groundStationList" in response
        assert len(response["groundStationList"]) == 10  # Mock catalog has 10 stations

        # Verify structure
        station = response["groundStationList"][0]
        assert "groundStationId" in station
        assert "groundStationName" in station
        assert "region" in station

    def test_ground_stations_have_valid_regions(self, provider, context):
        """Test that ground stations are in valid AWS regions."""
        response = provider.list_ground_stations(context=context)

        valid_regions = {
            "us-east-1",
            "us-east-2",
            "us-west-2",
            "ap-southeast-2",
            "ap-northeast-2",
            "eu-north-1",
            "eu-west-1",
            "me-south-1",
            "af-south-1",
            "sa-east-1",
        }

        for station in response["groundStationList"]:
            assert station["region"] in valid_regions

    def test_ground_stations_include_ohio(self, provider, context):
        """Test that Ohio Ground Station exists."""
        response = provider.list_ground_stations(context=context)

        names = [s["groundStationName"] for s in response["groundStationList"]]
        assert "Ohio Ground Station" in names

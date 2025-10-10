"""Utility functions and mock data catalogs for Ground Station service.

This module provides:
- Mock satellite catalog (10 satellites)
- Mock ground station catalog (10 ground stations)
- Helper functions for resource management
"""

from localstack.aws.api.groundstation import ResourceNotFoundException

from .models import GroundStationData, SatelliteData

# Mock Satellite Catalog (read-only)
# Using UUID format for satellite IDs to match AWS ARN requirements
MOCK_SATELLITES: list[SatelliteData] = [
    SatelliteData(
        satellite_id="11111111-1111-1111-1111-000000025544",
        satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/11111111-1111-1111-1111-000000025544",
        satellite_name="ISS (ZARYA)",
        norad_satellite_id=25544,
        ground_stations=["Ohio Ground Station", "Oregon Ground Station", "Hawaii Ground Station"],
    ),
    SatelliteData(
        satellite_id="22222222-2222-2222-2222-000000043013",
        satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/22222222-2222-2222-2222-000000043013",
        satellite_name="LANDSAT 8",
        norad_satellite_id=43013,
        ground_stations=["Ohio Ground Station", "Alaska Ground Station", "Sweden Ground Station"],
    ),
    SatelliteData(
        satellite_id="33333333-3333-3333-3333-000000040069",
        satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/33333333-3333-3333-3333-000000040069",
        satellite_name="AQUA",
        norad_satellite_id=40069,
        ground_stations=["Alaska Ground Station", "Hawaii Ground Station", "Sweden Ground Station"],
    ),
    SatelliteData(
        satellite_id="44444444-4444-4444-4444-000000025338",
        satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/44444444-4444-4444-4444-000000025338",
        satellite_name="NOAA 15",
        norad_satellite_id=25338,
        ground_stations=["Ohio Ground Station", "Oregon Ground Station"],
    ),
    SatelliteData(
        satellite_id="55555555-5555-5555-5555-000000028654",
        satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/55555555-5555-5555-5555-000000028654",
        satellite_name="NOAA 18",
        norad_satellite_id=28654,
        ground_stations=["Ohio Ground Station", "Alaska Ground Station"],
    ),
    SatelliteData(
        satellite_id="66666666-6666-6666-6666-000000033591",
        satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/66666666-6666-6666-6666-000000033591",
        satellite_name="NOAA 19",
        norad_satellite_id=33591,
        ground_stations=["Oregon Ground Station", "Hawaii Ground Station"],
    ),
    SatelliteData(
        satellite_id="77777777-7777-7777-7777-000000037849",
        satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/77777777-7777-7777-7777-000000037849",
        satellite_name="SUOMI NPP",
        norad_satellite_id=37849,
        ground_stations=["Alaska Ground Station", "Sweden Ground Station"],
    ),
    SatelliteData(
        satellite_id="88888888-8888-8888-8888-000000027424",
        satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/88888888-8888-8888-8888-000000027424",
        satellite_name="TERRA",
        norad_satellite_id=27424,
        ground_stations=["Ohio Ground Station", "Sweden Ground Station"],
    ),
    SatelliteData(
        satellite_id="99999999-9999-9999-9999-000000043226",
        satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/99999999-9999-9999-9999-000000043226",
        satellite_name="JPSS-1 (NOAA-20)",
        norad_satellite_id=43226,
        ground_stations=["Alaska Ground Station", "Oregon Ground Station"],
    ),
    SatelliteData(
        satellite_id="aaaaaaaa-aaaa-aaaa-aaaa-000000025994",
        satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/aaaaaaaa-aaaa-aaaa-aaaa-000000025994",
        satellite_name="METOP-A",
        norad_satellite_id=25994,
        ground_stations=["Hawaii Ground Station", "Sweden Ground Station"],
    ),
]


# Mock Ground Station Catalog (read-only)
MOCK_GROUND_STATIONS: list[GroundStationData] = [
    GroundStationData(
        ground_station_id="gs-us-east-1-ohio",
        ground_station_arn="arn:aws:groundstation:us-east-1:000000000000:ground-station/gs-us-east-1-ohio",
        ground_station_name="Ohio Ground Station",
        region="us-east-1",
    ),
    GroundStationData(
        ground_station_id="gs-us-west-2-oregon",
        ground_station_arn="arn:aws:groundstation:us-west-2:000000000000:ground-station/gs-us-west-2-oregon",
        ground_station_name="Oregon Ground Station",
        region="us-west-2",
    ),
    GroundStationData(
        ground_station_id="gs-us-west-2-alaska",
        ground_station_arn="arn:aws:groundstation:us-west-2:000000000000:ground-station/gs-us-west-2-alaska",
        ground_station_name="Alaska Ground Station",
        region="us-west-2",
    ),
    GroundStationData(
        ground_station_id="gs-us-west-2-hawaii",
        ground_station_arn="arn:aws:groundstation:us-west-2:000000000000:ground-station/gs-us-west-2-hawaii",
        ground_station_name="Hawaii Ground Station",
        region="us-west-2",
    ),
    GroundStationData(
        ground_station_id="gs-eu-north-1-sweden",
        ground_station_arn="arn:aws:groundstation:eu-north-1:000000000000:ground-station/gs-eu-north-1-sweden",
        ground_station_name="Sweden Ground Station",
        region="eu-north-1",
    ),
    GroundStationData(
        ground_station_id="gs-ap-southeast-2-australia",
        ground_station_arn="arn:aws:groundstation:ap-southeast-2:000000000000:ground-station/gs-ap-southeast-2-australia",
        ground_station_name="Australia Ground Station",
        region="ap-southeast-2",
    ),
    GroundStationData(
        ground_station_id="gs-me-south-1-bahrain",
        ground_station_arn="arn:aws:groundstation:me-south-1:000000000000:ground-station/gs-me-south-1-bahrain",
        ground_station_name="Bahrain Ground Station",
        region="me-south-1",
    ),
    GroundStationData(
        ground_station_id="gs-af-south-1-capetown",
        ground_station_arn="arn:aws:groundstation:af-south-1:000000000000:ground-station/gs-af-south-1-capetown",
        ground_station_name="Cape Town Ground Station",
        region="af-south-1",
    ),
    GroundStationData(
        ground_station_id="gs-sa-east-1-brazil",
        ground_station_arn="arn:aws:groundstation:sa-east-1:000000000000:ground-station/gs-sa-east-1-brazil",
        ground_station_name="Brazil Ground Station",
        region="sa-east-1",
    ),
    GroundStationData(
        ground_station_id="gs-ap-northeast-2-seoul",
        ground_station_arn="arn:aws:groundstation:ap-northeast-2:000000000000:ground-station/gs-ap-northeast-2-seoul",
        ground_station_name="Seoul Ground Station",
        region="ap-northeast-2",
    ),
]


def get_satellite_by_id(satellite_id: str) -> SatelliteData | None:
    """Get satellite from mock catalog by ID.

    Args:
        satellite_id: Satellite ID (NORAD ID)

    Returns:
        SatelliteData if found, None otherwise

    Raises:
        ResourceNotFoundException: If satellite not found
    """
    for satellite in MOCK_SATELLITES:
        if satellite.satellite_id == satellite_id:
            return satellite

    raise ResourceNotFoundException(f"Satellite with ID {satellite_id} not found")


def get_ground_station_by_name(ground_station_name: str) -> GroundStationData | None:
    """Get ground station from mock catalog by name.

    Args:
        ground_station_name: Ground station name

    Returns:
        GroundStationData if found, None otherwise

    Raises:
        ResourceNotFoundException: If ground station not found
    """
    for gs in MOCK_GROUND_STATIONS:
        if gs.ground_station_name == ground_station_name:
            return gs

    raise ResourceNotFoundException(f"Ground station '{ground_station_name}' not found")

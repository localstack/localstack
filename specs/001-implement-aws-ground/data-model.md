# Data Model: AWS Ground Station Service

**Date**: 2025-10-03
**Feature**: AWS Ground Station Service Implementation

## Overview

This document defines the data models for the AWS Ground Station service implementation in LocalStack. All models align with AWS Ground Station API specifications from botocore and support LocalStack's multi-account, multi-region architecture with Cloud Pods persistence.

## Storage Architecture

```python
from localstack.services.stores import AccountRegionBundle, BaseStore

class GroundStationStore(BaseStore):
    """
    Ground Station service state storage.
    All collections use AccountRegionBundle for multi-account/region isolation.
    """
    # Resource collections
    configs: AccountRegionBundle[Dict[str, ConfigData]]
    mission_profiles: AccountRegionBundle[Dict[str, MissionProfileData]]
    contacts: AccountRegionBundle[Dict[str, ContactData]]
    dataflow_endpoint_groups: AccountRegionBundle[Dict[str, DataflowEndpointGroupData]]

    # Tags collection (resource ARN → tags dict)
    tags: AccountRegionBundle[Dict[str, Dict[str, str]]]
```

## Entity Definitions

### 1. Config

Represents various configuration types for ground station operations.

**Entity**: `ConfigData`

**Attributes**:
```python
@dataclass
class ConfigData:
    config_id: str                    # UUID v4
    config_arn: str                   # arn:aws:groundstation:region:account:config/type/id
    config_type: ConfigType           # Enum: antenna-downlink, antenna-downlink-demod-decode, etc.
    name: str                         # User-provided name
    config_data: Dict[str, Any]       # Type-specific configuration (matches botocore schema)
    tags: Dict[str, str]              # Resource tags
    created_at: datetime              # Creation timestamp
    updated_at: datetime              # Last update timestamp
```

**Config Types** (ConfigType enum):
1. `antenna-downlink` - AntennaDownlinkConfig
2. `antenna-downlink-demod-decode` - AntennaDownlinkDemodDecodeConfig
3. `antenna-uplink` - AntennaUplinkConfig
4. `dataflow-endpoint` - DataflowEndpointConfig
5. `tracking` - TrackingConfig
6. `uplink-echo` - UplinkEchoConfig

**Validation Rules**:
- `config_id`: Must be valid UUID v4
- `config_arn`: Must match pattern `arn:aws:groundstation:{region}:{account}:config/{type}/{id}`
- `config_type`: Must be one of six valid types
- `config_data`: Must conform to botocore schema for the specific config type
- `name`: 1-256 characters
- Frequency validation (for antenna configs):
  - S-band: 2-4 GHz
  - X-band: 8-12 GHz
  - Ka-band: 26-40 GHz

**Relationships**:
- Referenced by: MissionProfile (via dataflow_edges, tracking_config_arn)
- Referenced by: UplinkEchoConfig (via antenna_uplink_config_arn)

**State Transitions**: None (immutable after creation, updates create new version)

**Example**:
```python
config_data = ConfigData(
    config_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    config_arn="arn:aws:groundstation:us-east-1:123456789012:config/antenna-downlink/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    config_type="antenna-downlink",
    name="S-Band Downlink Config",
    config_data={
        "antennaDownlinkConfig": {
            "spectrumConfig": {
                "centerFrequency": {"value": 2200.0, "units": "MHz"},
                "bandwidth": {"value": 15.0, "units": "MHz"}
            }
        }
    },
    tags={"Environment": "Production"},
    created_at=datetime.utcnow(),
    updated_at=datetime.utcnow()
)
```

### 2. MissionProfile

Defines communication parameters for satellite contacts.

**Entity**: `MissionProfileData`

**Attributes**:
```python
@dataclass
class MissionProfileData:
    mission_profile_id: str           # UUID v4
    mission_profile_arn: str          # arn:aws:groundstation:region:account:mission-profile/id
    name: str                         # Required, user-provided name
    minimum_viable_contact_duration_seconds: int  # Minimum contact duration
    contact_pre_pass_duration_minutes: int        # 1-120 minutes
    contact_post_pass_duration_minutes: int       # 1-120 minutes
    dataflow_edges: List[List[str]]   # Ordered list of [source_arn, dest_arn] pairs
    tracking_config_arn: Optional[str]            # Optional tracking config ARN
    streams_kms_key_arn: Optional[str]            # Optional KMS key ARN
    tags: Dict[str, str]              # Resource tags
    created_at: datetime              # Creation timestamp
    updated_at: datetime              # Last update timestamp
```

**Validation Rules**:
- `mission_profile_id`: Must be valid UUID v4
- `mission_profile_arn`: Must match pattern `arn:aws:groundstation:{region}:{account}:mission-profile/{id}`
- `name`: 1-256 characters, required
- `contact_pre_pass_duration_minutes`: 1-120 (validated per spec)
- `contact_post_pass_duration_minutes`: 1-120 (validated per spec)
- `dataflow_edges`: Each pair must be valid ordered config ARNs with allowed type transitions
- `tracking_config_arn`: Must be valid tracking config ARN if provided
- `streams_kms_key_arn`: Must be valid KMS ARN if provided

**Dataflow Edge Validation**:
```python
# Valid transitions (source_type, dest_type)
VALID_TRANSITIONS = {
    ("antenna-downlink", "dataflow-endpoint"),
    ("antenna-downlink-demod-decode", "dataflow-endpoint"),
    ("antenna-uplink", "uplink-echo"),
    ("uplink-echo", "dataflow-endpoint"),
}
```

**Relationships**:
- References: Config (via dataflow_edges and tracking_config_arn)
- Referenced by: Contact (via mission_profile_arn)

**State Transitions**: None (can be updated via UpdateMissionProfile)

**Example**:
```python
mission_profile = MissionProfileData(
    mission_profile_id="mp-12345678-1234-5678-abcd-123456789012",
    mission_profile_arn="arn:aws:groundstation:us-east-1:123456789012:mission-profile/mp-12345678-1234-5678-abcd-123456789012",
    name="LEO Satellite Mission",
    minimum_viable_contact_duration_seconds=180,
    contact_pre_pass_duration_minutes=5,
    contact_post_pass_duration_minutes=3,
    dataflow_edges=[
        ["arn:aws:groundstation:us-east-1:123456789012:config/antenna-downlink/config1",
         "arn:aws:groundstation:us-east-1:123456789012:config/dataflow-endpoint/config2"]
    ],
    tracking_config_arn="arn:aws:groundstation:us-east-1:123456789012:config/tracking/config3",
    streams_kms_key_arn=None,
    tags={"Mission": "Earth Observation"},
    created_at=datetime.utcnow(),
    updated_at=datetime.utcnow()
)
```

### 3. Contact

Represents a scheduled satellite communication window.

**Entity**: `ContactData`

**Attributes**:
```python
@dataclass
class ContactData:
    contact_id: str                   # UUID v4
    contact_arn: str                  # arn:aws:groundstation:region:account:contact/id
    contact_name: Optional[str]       # Optional user-provided name
    ground_station: str               # Ground station name (validated against catalog)
    mission_profile_arn: str          # Mission profile ARN
    satellite_arn: str                # Satellite ARN
    start_time: datetime              # Contact start time (UTC)
    end_time: datetime                # Contact end time (UTC)
    contact_status: ContactStatus     # State machine: SCHEDULING, SCHEDULED, PASS, COMPLETED, FAILED, CANCELLED
    error_message: Optional[str]      # Error message if FAILED
    maximum_elevation: Optional[float]  # Maximum elevation angle (degrees)
    post_pass_end_time: Optional[datetime]  # End of post-pass period
    pre_pass_start_time: Optional[datetime]  # Start of pre-pass period
    region: str                       # AWS region
    tags: Dict[str, str]              # Resource tags
    created_at: datetime              # Creation timestamp (when reserved)
    updated_at: datetime              # Last status update timestamp
```

**Contact States** (ContactStatus enum):
```python
class ContactStatus(str, Enum):
    SCHEDULING = "SCHEDULING"    # Initial state when reserving
    SCHEDULED = "SCHEDULED"      # Successfully reserved
    PASS = "PASS"               # Contact window active (current time >= start_time)
    COMPLETED = "COMPLETED"      # Contact finished (current time >= end_time)
    FAILED = "FAILED"           # Contact failed (error occurred)
    CANCELLED = "CANCELLED"      # User cancelled the contact
```

**State Transition Rules**:
```
SCHEDULING → SCHEDULED (when successfully reserved)
SCHEDULED → PASS (when current_time >= start_time, automatic via background timer)
PASS → COMPLETED (when current_time >= end_time, automatic via background timer)
SCHEDULED/PASS → CANCELLED (user calls CancelContact)
SCHEDULED/PASS → FAILED (system error occurs)
```

**Validation Rules**:
- `contact_id`: Must be valid UUID v4
- `contact_arn`: Must match pattern `arn:aws:groundstation:{region}:{account}:contact/{id}`
- `ground_station`: Must exist in predefined ground station catalog
- `mission_profile_arn`: Must reference existing mission profile
- `satellite_arn`: Must reference existing satellite
- `start_time`: Must be in the future when reserving
- `end_time`: Must be after start_time
- Contact duration: end_time - start_time must be >= mission_profile.minimum_viable_contact_duration_seconds

**Relationships**:
- References: MissionProfile (via mission_profile_arn)
- References: Satellite (via satellite_arn)
- References: GroundStation (via ground_station name)

**Background State Management**:
- Background thread checks all SCHEDULED/PASS contacts every 5 seconds
- Automatically transitions SCHEDULED → PASS when current_time >= start_time
- Automatically transitions PASS → COMPLETED when current_time >= end_time
- Persists state changes to store for Cloud Pods support

**Example**:
```python
contact = ContactData(
    contact_id="c-12345678-1234-5678-abcd-123456789012",
    contact_arn="arn:aws:groundstation:us-east-1:123456789012:contact/c-12345678-1234-5678-abcd-123456789012",
    contact_name="ISS Pass 2025-10-04",
    ground_station="Ohio Ground Station",
    mission_profile_arn="arn:aws:groundstation:us-east-1:123456789012:mission-profile/mp-12345678-1234-5678-abcd-123456789012",
    satellite_arn="arn:aws:groundstation:us-east-1:123456789012:satellite/25544",
    start_time=datetime(2025, 10, 4, 10, 0, 0),
    end_time=datetime(2025, 10, 4, 10, 15, 0),
    contact_status=ContactStatus.SCHEDULED,
    error_message=None,
    maximum_elevation=45.0,
    pre_pass_start_time=datetime(2025, 10, 4, 9, 55, 0),
    post_pass_end_time=datetime(2025, 10, 4, 10, 18, 0),
    region="us-east-1",
    tags={"Satellite": "ISS"},
    created_at=datetime.utcnow(),
    updated_at=datetime.utcnow()
)
```

### 4. DataflowEndpointGroup

Groups multiple dataflow endpoints for data delivery.

**Entity**: `DataflowEndpointGroupData`

**Attributes**:
```python
@dataclass
class DataflowEndpointData:
    name: str                         # Endpoint name
    address: EndpointAddress          # IP address and port
    mtu: Optional[int]                # Maximum Transmission Unit (bytes)

@dataclass
class EndpointAddress:
    name: str                         # Socket address name
    port: int                         # Port number (1-65535)

@dataclass
class DataflowEndpointGroupData:
    dataflow_endpoint_group_id: str   # UUID v4
    dataflow_endpoint_group_arn: str  # arn:aws:groundstation:region:account:dataflow-endpoint-group/id
    endpoints: List[DataflowEndpointData]  # List of endpoints (at least 1 required)
    tags: Dict[str, str]              # Resource tags
    created_at: datetime              # Creation timestamp
```

**Validation Rules**:
- `dataflow_endpoint_group_id`: Must be valid UUID v4
- `dataflow_endpoint_group_arn`: Must match pattern `arn:aws:groundstation:{region}:{account}:dataflow-endpoint-group/{id}`
- `endpoints`: Must contain at least one endpoint
- Each endpoint:
  - `name`: 1-256 characters
  - `address.name`: Valid IP address or hostname
  - `address.port`: 1-65535
  - `mtu`: If provided, must be > 0

**Relationships**:
- Referenced by: Config (DataflowEndpointConfig references endpoint group)

**State Transitions**: None (can be updated via update operation)

**Example**:
```python
endpoint_group = DataflowEndpointGroupData(
    dataflow_endpoint_group_id="deg-12345678-1234-5678-abcd-123456789012",
    dataflow_endpoint_group_arn="arn:aws:groundstation:us-east-1:123456789012:dataflow-endpoint-group/deg-12345678-1234-5678-abcd-123456789012",
    endpoints=[
        DataflowEndpointData(
            name="Primary Endpoint",
            address=EndpointAddress(name="192.168.1.100", port=55888),
            mtu=1500
        ),
        DataflowEndpointData(
            name="Backup Endpoint",
            address=EndpointAddress(name="192.168.1.101", port=55888),
            mtu=1500
        )
    ],
    tags={"Environment": "Production"},
    created_at=datetime.utcnow()
)
```

### 5. Satellite (Read-Only Mock Catalog)

Represents satellite information for testing.

**Entity**: `SatelliteData`

**Attributes**:
```python
@dataclass
class SatelliteData:
    satellite_id: str                 # NORAD ID (e.g., "25544")
    satellite_arn: str                # arn:aws:groundstation:region:account:satellite/id
    satellite_name: str               # Human-readable name (e.g., "ISS")
    norad_satellite_id: int           # NORAD catalog number
    ground_stations: List[str]        # List of compatible ground station names
```

**Mock Catalog** (10 satellites):
```python
MOCK_SATELLITES = [
    SatelliteData(satellite_id="25544", satellite_arn="...", satellite_name="ISS", norad_satellite_id=25544, ground_stations=["Ohio Ground Station", "Oregon Ground Station"]),
    SatelliteData(satellite_id="27424", satellite_arn="...", satellite_name="Aqua", norad_satellite_id=27424, ground_stations=["Ohio Ground Station", "Sydney Ground Station"]),
    SatelliteData(satellite_id="25994", satellite_arn="...", satellite_name="Terra", norad_satellite_id=25994, ground_stations=["Ohio Ground Station", "Ireland Ground Station"]),
    SatelliteData(satellite_id="37849", satellite_arn="...", satellite_name="Suomi NPP", norad_satellite_id=37849, ground_stations=["Oregon Ground Station", "Tokyo Ground Station"]),
    SatelliteData(satellite_id="43013", satellite_arn="...", satellite_name="JPSS-1", norad_satellite_id=43013, ground_stations=["Stockholm Ground Station", "Sydney Ground Station"]),
    SatelliteData(satellite_id="39084", satellite_arn="...", satellite_name="Landsat 8", norad_satellite_id=39084, ground_stations=["Oregon Ground Station", "São Paulo Ground Station"]),
    SatelliteData(satellite_id="49260", satellite_arn="...", satellite_name="Landsat 9", norad_satellite_id=49260, ground_stations=["Ohio Ground Station", "Cape Town Ground Station"]),
    SatelliteData(satellite_id="39634", satellite_arn="...", satellite_name="Sentinel-1A", norad_satellite_id=39634, ground_stations=["Ireland Ground Station", "Bahrain Ground Station"]),
    SatelliteData(satellite_id="40697", satellite_arn="...", satellite_name="Sentinel-2A", norad_satellite_id=40697, ground_stations=["Ireland Ground Station", "Stockholm Ground Station"]),
    SatelliteData(satellite_id="29499", satellite_arn="...", satellite_name="MetOp-A", norad_satellite_id=29499, ground_stations=["Stockholm Ground Station", "Bahrain Ground Station"]),
]
```

**Validation Rules**:
- Read-only catalog (no create/update/delete operations)
- `satellite_id` must exist in catalog for Contact reservation

**Relationships**:
- Referenced by: Contact (via satellite_arn)

### 6. GroundStation (Read-Only Mock Catalog)

Represents ground station information for testing.

**Entity**: `GroundStationData`

**Attributes**:
```python
@dataclass
class GroundStationData:
    ground_station_id: str            # Unique identifier
    ground_station_arn: str           # arn:aws:groundstation:region:account:ground-station/id
    ground_station_name: str          # Human-readable name
    region: str                       # AWS region
```

**Mock Catalog** (10 ground stations):
```python
MOCK_GROUND_STATIONS = [
    GroundStationData(ground_station_id="gs-us-east-1", ground_station_arn="...", ground_station_name="Ohio Ground Station", region="us-east-1"),
    GroundStationData(ground_station_id="gs-us-east-2", ground_station_arn="...", ground_station_name="Ohio Ground Station 2", region="us-east-2"),
    GroundStationData(ground_station_id="gs-us-west-2", ground_station_arn="...", ground_station_name="Oregon Ground Station", region="us-west-2"),
    GroundStationData(ground_station_id="gs-eu-west-1", ground_station_arn="...", ground_station_name="Ireland Ground Station", region="eu-west-1"),
    GroundStationData(ground_station_id="gs-eu-north-1", ground_station_arn="...", ground_station_name="Stockholm Ground Station", region="eu-north-1"),
    GroundStationData(ground_station_id="gs-ap-southeast-2", ground_station_arn="...", ground_station_name="Sydney Ground Station", region="ap-southeast-2"),
    GroundStationData(ground_station_id="gs-me-south-1", ground_station_arn="...", ground_station_name="Bahrain Ground Station", region="me-south-1"),
    GroundStationData(ground_station_id="gs-af-south-1", ground_station_arn="...", ground_station_name="Cape Town Ground Station", region="af-south-1"),
    GroundStationData(ground_station_id="gs-sa-east-1", ground_station_arn="...", ground_station_name="São Paulo Ground Station", region="sa-east-1"),
    GroundStationData(ground_station_id="gs-ap-northeast-1", ground_station_arn="...", ground_station_name="Tokyo Ground Station", region="ap-northeast-1"),
]
```

**Validation Rules**:
- Read-only catalog (no create/update/delete operations)
- `ground_station_name` must exist in catalog for Contact reservation

**Relationships**:
- Referenced by: Contact (via ground_station name)

## Entity Relationship Diagram

```
┌─────────────────┐
│    Config       │
│  (6 types)      │
└────────┬────────┘
         │
         │ referenced by
         ▼
┌─────────────────┐         ┌─────────────────┐
│ MissionProfile  │────────▶│    Contact      │
└────────┬────────┘ refs    └────────┬────────┘
         │                           │
         │                           │ refs
         ▼                           ▼
┌─────────────────┐         ┌─────────────────┐
│ DataflowEndpoint│         │   Satellite     │
│      Group      │         │  (read-only)    │
└─────────────────┘         └─────────────────┘

                            ┌─────────────────┐
                            │  GroundStation  │
                            │  (read-only)    │
                            └─────────────────┘
```

## Storage Indexes

For efficient queries, the following indexes should be maintained:

1. **Configs by Type**: `config_type → List[config_id]` for ListConfigs filtering
2. **Contacts by Status**: `contact_status → List[contact_id]` for background timer efficiency
3. **Contacts by Time**: Sorted by `start_time` for pagination and timer checks
4. **Tags by ARN**: `resource_arn → tags_dict` for TagResource/UntagResource

## Persistence Considerations

All entities support Cloud Pods persistence via AccountRegionBundle:
- Automatic serialization/deserialization
- Multi-account and multi-region isolation preserved
- Contact state machines resume correctly after LocalStack restart
- Background timer re-initializes by scanning contact times on startup

## Validation Summary

| Entity | Key Validations |
|--------|-----------------|
| Config | UUID format, ARN format, frequency ranges (S/X/Ka-band), config schema |
| MissionProfile | UUID format, ARN format, duration ranges (1-120 min), dataflow edge types |
| Contact | UUID format, ARN format, time logic (end > start > now), ground station exists, satellite exists |
| DataflowEndpointGroup | UUID format, ARN format, at least 1 endpoint, port range (1-65535) |
| Satellite | Read-only, ID must exist in catalog |
| GroundStation | Read-only, name must exist in catalog |

## Next Steps

Use these data models to:
1. Generate API contracts (OpenAPI specs) - see contracts/
2. Create contract tests validating request/response schemas
3. Implement provider methods following these schemas
4. Generate integration test scenarios - see quickstart.md
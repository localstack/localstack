# AWS Ground Station Service

LocalStack implementation of the AWS Ground Station service for satellite communication workflows.

## Overview

AWS Ground Station is a fully managed service that provides satellite ground station infrastructure. This LocalStack implementation provides a complete emulation of Ground Station APIs for local development and testing.

## Features

### Implemented Operations (29 APIs)

**Configuration Management**
- `CreateConfig` - Create antenna, tracking, and dataflow configurations
- `GetConfig` - Retrieve configuration details
- `UpdateConfig` - Modify existing configurations
- `DeleteConfig` - Remove configurations (with dependency checking)
- `ListConfigs` - List all configurations

**Mission Profiles**
- `CreateMissionProfile` - Define mission parameters and dataflow edges
- `GetMissionProfile` - Retrieve mission profile details
- `UpdateMissionProfile` - Modify mission profiles
- `DeleteMissionProfile` - Remove mission profiles (with active contact checking)
- `ListMissionProfiles` - List all mission profiles

**Contact Management**
- `ReserveContact` - Schedule satellite contact windows
- `DescribeContact` - Get contact details and status
- `ListContacts` - Query contacts by time range and status
- `CancelContact` - Cancel scheduled contacts

**Dataflow Endpoint Groups**
- `CreateDataflowEndpointGroup` - Define data reception endpoints
- `GetDataflowEndpointGroup` - Retrieve endpoint details
- `DeleteDataflowEndpointGroup` - Remove endpoint groups
- `ListDataflowEndpointGroups` - List all endpoint groups

**Satellite & Ground Station Discovery**
- `ListSatellites` - Browse available satellites (10 mock satellites)
- `GetSatellite` - Get satellite details by ID
- `ListGroundStations` - Browse ground stations (10 global locations)

**Resource Tagging**
- `TagResource` - Add tags to resources
- `UntagResource` - Remove tags from resources
- `ListTagsForResource` - List resource tags

**Usage Tracking**
- `GetMinuteUsage` - Track scheduled contact minutes

## Mock Satellite Catalog

LocalStack provides 10 pre-configured satellites:

| Satellite | NORAD ID | Coverage |
|-----------|----------|----------|
| ISS (ZARYA) | 25544 | Ohio, Oregon, Hawaii |
| LANDSAT 8 | 43013 | Ohio, Alaska, Sweden |
| AQUA | 40069 | Alaska, Hawaii, Sweden |
| NOAA 15 | 25338 | Ohio, Oregon |
| NOAA 18 | 28654 | Ohio, Alaska |
| NOAA 19 | 33591 | Oregon, Hawaii |
| SUOMI NPP | 37849 | Alaska, Sweden |
| TERRA | 27424 | Ohio, Sweden |
| JPSS-1 (NOAA-20) | 43226 | Alaska, Oregon |
| METOP-A | 25994 | Hawaii, Sweden |

## Mock Ground Station Network

10 globally distributed ground stations:

| Location | Region | ID |
|----------|--------|-----|
| Ohio | us-east-1 | gs-us-east-1-ohio |
| Ohio-2 | us-east-2 | gs-us-east-2-ohio2 |
| Oregon | us-west-2 | gs-us-west-2-oregon |
| Alaska | us-west-2 | gs-us-west-2-alaska |
| Hawaii | us-west-2 | gs-us-west-2-hawaii |
| Sydney | ap-southeast-2 | gs-ap-southeast-2-sydney |
| Sweden | eu-north-1 | gs-eu-north-1-sweden |
| Ireland | eu-west-1 | gs-eu-west-1-ireland |
| South Korea | ap-northeast-2 | gs-ap-northeast-2-korea |
| Bahrain | me-south-1 | gs-me-south-1-bahrain |

## Configuration Types

### 1. Antenna Downlink
Receive data from satellite:
```json
{
  "antennaDownlinkConfig": {
    "spectrumConfig": {
      "centerFrequency": {"value": 2200.0, "units": "MHz"},
      "bandwidth": {"value": 125.0, "units": "MHz"}
    }
  }
}
```

### 2. Antenna Uplink
Send data to satellite:
```json
{
  "antennaUplinkConfig": {
    "spectrumConfig": {
      "centerFrequency": {"value": 8400.0, "units": "MHz"}
    },
    "targetEirp": {"value": 30.0, "units": "dBW"}
  }
}
```

### 3. Tracking
Satellite tracking configuration:
```json
{
  "trackingConfig": {
    "autotrack": "REQUIRED"
  }
}
```

### 4. Dataflow Endpoint
Data destination configuration:
```json
{
  "dataflowEndpointConfig": {
    "dataflowEndpointName": "my-endpoint",
    "dataflowEndpointRegion": "us-east-1"
  }
}
```

### 5. Uplink Echo
Echo uplink signals:
```json
{
  "uplinkEchoConfig": {
    "enabled": true,
    "antennaUplinkConfigArn": "arn:aws:groundstation:..."
  }
}
```

### 6. Antenna Downlink Demod Decode
Demodulate and decode downlink:
```json
{
  "antennaDownlinkDemodDecodeConfig": {
    "spectrumConfig": {...},
    "demodulationConfig": {"unvalidatedJSON": "{...}"},
    "decodeConfig": {"unvalidatedJSON": "{...}"}
  }
}
```

## Validation Rules

### Frequency Ranges
- **S-band**: 2000-4000 MHz
- **X-band**: 8000-12000 MHz
- **Ka-band**: 26000-40000 MHz (26-40 GHz)

### EIRP (Effective Isotropic Radiated Power)
- Range: -10 to 50 dBW

### Contact Durations
- Pre-pass: 1-7200 seconds
- Post-pass: 1-7200 seconds
- Minimum viable: 1-21600 seconds

### Tags
- Maximum 50 tags per resource
- Key: 1-128 characters
- Value: 0-256 characters

### IAM Roles
- Format: `arn:aws:iam::ACCOUNT:role/ROLENAME`
- Validated when creating dataflow endpoint groups

## Contact State Transitions

The ContactStateManager automatically transitions contact states:

```
SCHEDULED --> PASS --> COMPLETED
     |
     v
  CANCELLED (manual)
```

- **SCHEDULED**: Contact reserved, waiting for start time
- **PASS**: Contact in progress (start_time ≤ now < end_time)
- **COMPLETED**: Contact finished (now ≥ end_time)
- **CANCELLED**: Manually cancelled
- **FAILED**: Contact failed (error condition)

State transitions occur automatically every 5 seconds via background thread.

## Example Workflows

### Complete Mission Setup

```bash
# 1. Create tracking configuration
aws groundstation create-config \
  --name "ISS-Tracking" \
  --config-data '{
    "trackingConfig": {
      "autotrack": "REQUIRED"
    }
  }' \
  --endpoint-url=http://localhost:4566

# 2. Create downlink configuration
aws groundstation create-config \
  --name "ISS-Downlink" \
  --config-data '{
    "antennaDownlinkConfig": {
      "spectrumConfig": {
        "centerFrequency": {"value": 2200.0, "units": "MHz"},
        "bandwidth": {"value": 125.0, "units": "MHz"}
      }
    }
  }' \
  --endpoint-url=http://localhost:4566

# 3. Create dataflow endpoint configuration
aws groundstation create-config \
  --name "ISS-DataFlow" \
  --config-data '{
    "dataflowEndpointConfig": {
      "dataflowEndpointName": "ISS-Receiver",
      "dataflowEndpointRegion": "us-east-1"
    }
  }' \
  --endpoint-url=http://localhost:4566

# 4. Create mission profile
aws groundstation create-mission-profile \
  --name "ISS-Mission" \
  --minimum-viable-contact-duration-seconds 60 \
  --contact-pre-pass-duration-seconds 120 \
  --contact-post-pass-duration-seconds 60 \
  --tracking-config-arn "arn:aws:groundstation:us-east-1:000000000000:config/tracking/..." \
  --dataflow-edges '[
    ["TRACKING_ARN", "DOWNLINK_ARN"],
    ["DOWNLINK_ARN", "DATAFLOW_ARN"]
  ]' \
  --endpoint-url=http://localhost:4566

# 5. Reserve contact
aws groundstation reserve-contact \
  --mission-profile-arn "arn:aws:groundstation:us-east-1:000000000000:mission-profile/..." \
  --satellite-arn "arn:aws:groundstation:us-east-1:000000000000:satellite/11111111-1111-1111-1111-000000025544" \
  --start-time "2026-01-01T12:00:00Z" \
  --end-time "2026-01-01T13:00:00Z" \
  --ground-station "Ohio Ground Station" \
  --endpoint-url=http://localhost:4566
```

## Architecture

### State Management
- **BaseStore with LocalAttribute**: Automatic account/region isolation
- **Cloud Pods**: State persistence across restarts
- **Background State Manager**: Automatic contact transitions

### Resource ARN Formats
```
Config:          arn:aws:groundstation:REGION:ACCOUNT:config/TYPE/UUID
Mission Profile: arn:aws:groundstation:REGION:ACCOUNT:mission-profile/UUID
Contact:         arn:aws:groundstation:REGION:ACCOUNT:contact/UUID
Endpoint Group:  arn:aws:groundstation:REGION:ACCOUNT:dataflow-endpoint-group/UUID
Satellite:       arn:aws:groundstation:REGION:ACCOUNT:satellite/UUID
```

### Dependencies
- Configs cannot be deleted if used by mission profiles
- Mission profiles cannot be deleted if they have active contacts
- Dataflow edges must reference existing configurations

## Testing

### Run Unit Tests
```bash
pytest tests/unit/services/groundstation/ -v
# 107 tests covering all operations
```

### Manual Testing
See `/tmp/test_*.sh` scripts for comprehensive API testing examples.

## Limitations

1. **Mock Catalogs**: Satellites and ground stations are pre-configured mock data
2. **No Actual Communication**: No real satellite communication occurs
3. **Simplified State Transitions**: Real AWS has more complex state machines
4. **No CloudWatch Integration**: Metrics not emitted (future enhancement)
5. **No EventBridge Events**: State change events not published (future enhancement)

## Development

### File Structure
```
localstack/services/groundstation/
├── __init__.py
├── provider.py          # Main API implementation
├── models.py            # Data models and store
├── validation.py        # Input validation
├── resource.py          # ARN generation
├── utils.py             # Mock catalogs and helpers
├── state_manager.py     # Background state transitions
└── README.md           # This file
```

### Adding New Features
1. Update `models.py` for new data structures
2. Add validation in `validation.py`
3. Implement operation in `provider.py`
4. Add tests in `tests/unit/services/groundstation/`

## References

- [AWS Ground Station Documentation](https://docs.aws.amazon.com/ground-station/)
- [AWS Ground Station API Reference](https://docs.aws.amazon.com/ground-station/latest/APIReference/)
- [LocalStack Ground Station Coverage](https://docs.localstack.cloud/references/coverage/coverage_groundstation/)

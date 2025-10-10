I# Research: AWS Ground Station Service for LocalStack

**Date**: 2025-10-03
**Feature**: AWS Ground Station Service Implementation
**Status**: Complete

## Overview

This document captures research findings and technical decisions for implementing the AWS Ground Station service in LocalStack. All research items have been resolved and technical approaches validated against LocalStack's architecture patterns and constitutional requirements.

## Research Areas

### 1. LocalStack ASF (AWS Service Framework) Patterns

**Question**: How should we structure the Ground Station service provider using LocalStack's ASF framework?

**Research Findings**:
- LocalStack uses a provider pattern where services implement auto-generated API interfaces from botocore
- The `GroundstationApi` interface is generated from botocore specifications at `localstack/aws/api/groundstation/`
- Service providers inherit from and implement these interfaces, ensuring type safety and AWS compatibility

**Decision**: Implement `GroundStationProvider` class that implements `GroundstationApi`

**Rationale**:
- Standard LocalStack pattern used across all services (lambda, s3, dynamodb)
- Automatic type checking from botocore specs
- Ensures AWS API compatibility by construction
- Simplifies maintenance when AWS updates their API

**Reference Implementations**:
- `localstack/services/lambda_/provider.py` - LambdaProvider implementing LambdaApi
- `localstack/services/s3/provider.py` - S3Provider implementing S3Api
- `localstack/services/dynamodb/provider.py` - DynamoDBProvider implementing DynamodbApi

**Example Pattern**:
```python
from localstack.aws.api.groundstation import GroundstationApi
from localstack.services.plugins import ServiceLifecycleHook

class GroundStationProvider(GroundstationApi, ServiceLifecycleHook):
    def create_config(self, request: CreateConfigRequest) -> CreateConfigResponse:
        # Implementation
        pass
```

### 2. State Management with AccountRegionBundle

**Question**: How should we manage state for Ground Station resources across multi-account and multi-region scenarios?

**Research Findings**:
- LocalStack provides `AccountRegionBundle` from `localstack.services.stores` for resource isolation
- Resources are automatically scoped to account ID and region
- Supports Cloud Pods persistence out of the box
- `BaseStore` provides standard storage interface with cross-region/account queries

**Decision**: Use `GroundStationStore` extending `BaseStore` with `AccountRegionBundle[ResourceType]`

**Rationale**:
- Built-in multi-account and multi-region isolation
- Cloud Pods support without additional code
- Consistent with LocalStack architecture
- Simplifies resource lookup and filtering

**Implementation Pattern**:
```python
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    LocalAttribute,
)

class GroundStationStore(BaseStore):
    configs: AccountRegionBundle[Dict[str, ConfigData]]
    mission_profiles: AccountRegionBundle[Dict[str, MissionProfileData]]
    contacts: AccountRegionBundle[Dict[str, ContactData]]
    # ... other resources
```

**Reference**: `localstack/services/lambda_/models.py`

### 3. Background Timer for Contact State Transitions

**Question**: How should we implement automatic contact state transitions (SCHEDULED → PASS → COMPLETED) based on start/end times?

**Clarification Context**: Per spec clarification, contacts must automatically transition states when their scheduled times are reached (not lazy evaluation on query).

**Research Findings**:
- LocalStack uses threading for background jobs
- Standard Python `threading.Timer` for scheduled one-time events
- Alternative: `threading.Thread` with continuous loop checking times
- Need to handle LocalStack restarts (re-initialize timers from persisted contacts)

**Decision**: Implement background thread that periodically checks contact start/end times and updates states

**Rationale**:
- Simple, reliable approach
- Survives LocalStack restarts by re-scanning contacts on startup
- Minimal resource overhead (check every 1-5 seconds)
- Aligns with clarification requirement for active state management

**Implementation Approach**:
```python
import threading
import time
from datetime import datetime

class ContactStateManager:
    def __init__(self, store: GroundStationStore):
        self.store = store
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._check_contacts, daemon=True)
        self.thread.start()

    def _check_contacts(self):
        while self.running:
            now = datetime.utcnow()
            # Scan all contacts, update states based on times
            time.sleep(5)  # Check every 5 seconds
```

**Edge Cases Handled**:
- LocalStack restart: Re-scan contacts on provider initialization
- Persistence: States saved via AccountRegionBundle automatically
- Past contacts: Handle contacts with times in the past appropriately

### 4. ARN Format and Validation

**Question**: What ARN patterns does AWS Ground Station use, and how should we generate/validate them?

**Research Findings**:
- AWS Ground Station ARN format documented in AWS documentation
- Different resource types have different ARN structures
- LocalStack has ARN utility functions in `localstack/utils/aws/arns.py`

**Decision**: Implement ARN patterns per AWS Ground Station specifications

**ARN Formats**:
```
Configs: arn:aws:groundstation:{region}:{account}:config/{config-type}/{config-id}
Mission Profiles: arn:aws:groundstation:{region}:{account}:mission-profile/{mission-profile-id}
Contacts: arn:aws:groundstation:{region}:{account}:contact/{contact-id}
Dataflow Endpoint Groups: arn:aws:groundstation:{region}:{account}:dataflow-endpoint-group/{group-id}
Satellites: arn:aws:groundstation:{region}:{account}:satellite/{satellite-id}
Ground Stations: arn:aws:groundstation:{region}:{account}:ground-station/{ground-station-id}
```

**Rationale**:
- AWS compatibility (Principle I)
- Enables IAM policy support
- Supports resource tagging via ARNs
- Allows resource references in mission profiles and contacts

**Implementation**:
```python
def create_config_arn(region: str, account_id: str, config_type: str, config_id: str) -> str:
    return f"arn:aws:groundstation:{region}:{account_id}:config/{config_type}/{config_id}"

def parse_config_arn(arn: str) -> Dict[str, str]:
    # Parse and validate ARN structure
    pass
```

**Reference**: AWS Ground Station documentation, `localstack/utils/aws/arns.py`

### 5. Dataflow Edge Validation

**Question**: How should dataflow edges in mission profiles be validated?

**Clarification Context**: Per spec clarification, dataflow edges are ordered pairs with specific config type sequence requirements (e.g., antenna config → dataflow endpoint config).

**Research Findings**:
- AWS Ground Station has specific rules for which config types can connect
- Edges form a data flow path from antenna to endpoint
- Order matters: source → destination

**Decision**: Implement ordered config ARN pair validation with type sequence rules

**Valid Config Type Transitions**:
```
AntennaDownlinkConfig → DataflowEndpointConfig
AntennaDownlinkDemodDecodeConfig → DataflowEndpointConfig
AntennaUplinkConfig → DataflowEndpointConfig (via UplinkEchoConfig)
TrackingConfig → (used separately, not in edges)
UplinkEchoConfig → DataflowEndpointConfig
```

**Rationale**:
- Matches AWS behavior
- Prevents invalid mission profile configurations
- Provides helpful error messages for users
- Aligns with clarification on ordered pairs

**Implementation**:
```python
VALID_DATAFLOW_TRANSITIONS = {
    ("antenna-downlink", "dataflow-endpoint"),
    ("antenna-downlink-demod-decode", "dataflow-endpoint"),
    ("antenna-uplink", "uplink-echo"),
    ("uplink-echo", "dataflow-endpoint"),
}

def validate_dataflow_edge(source_config_arn: str, dest_config_arn: str) -> bool:
    source_type = get_config_type_from_arn(source_config_arn)
    dest_type = get_config_type_from_arn(dest_config_arn)
    return (source_type, dest_type) in VALID_DATAFLOW_TRANSITIONS
```

### 6. Testing Approach

**Question**: What testing strategy should we use to meet the 80% coverage requirement and LocalStack's 14 rules for stable tests?

**Research Findings**:
- LocalStack's 14 rules (R01-R14) documented in testing guidelines
- `@markers.aws.validated` decorator for AWS parity tests
- Separation of unit tests (`tests/unit/`) and integration tests (`tests/aws/`)
- Pytest fixtures for LocalStack client setup

**Decision**: Three-tier testing approach

**Test Tiers**:
1. **Unit Tests** (`tests/unit/services/groundstation/`):
   - Test each function/method in isolation
   - Mock external dependencies
   - Fast execution (<1ms per test)
   - Files: `test_provider.py`, `test_models.py`, `test_validation.py`, `test_resource.py`

2. **Integration Tests** (`tests/aws/services/groundstation/`):
   - Test API operations end-to-end
   - Use LocalStack test client (not mocked)
   - Validate request/response schemas
   - Files: `test_configs.py`, `test_mission_profiles.py`, `test_contacts.py`, etc.

3. **AWS Parity Tests** (using `@markers.aws.validated`):
   - Validate behavior matches real AWS
   - Run against both LocalStack and AWS
   - Focus on edge cases and error conditions

**Rationale**:
- Meets 80% coverage requirement
- Follows LocalStack's established patterns
- Supports R01-R14 compliance (idempotent, isolated, fast)
- Enables AWS compatibility validation

**Example Test Structure**:
```python
# Integration test with AWS parity
@markers.aws.validated
def test_create_config(aws_client):
    response = aws_client.groundstation.create_config(
        name="test-config",
        configData={
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2200.0, "units": "MHz"},
                    "bandwidth": {"value": 15.0, "units": "MHz"}
                }
            }
        }
    )
    assert "configArn" in response
    assert response["configType"] == "antenna-downlink"
```

**Reference**: `tests/aws/services/lambda_/test_lambda.py`, `tests/unit/services/lambda_/test_lambda_executors.py`

### 7. Mock Satellite and Ground Station Catalogs

**Question**: What satellites and ground stations should be included in the mock catalogs?

**Research Findings**:
- AWS Ground Station provides access to real satellites (ISS, Aqua, Terra, etc.)
- Ground stations located in various AWS regions globally
- For LocalStack, we need realistic mock data for testing

**Decision**: Provide 10-15 mock satellites and ground stations matching real AWS Ground Station offerings

**Mock Satellites** (10-15 examples):
1. ISS (International Space Station) - NORAD ID: 25544
2. Aqua - NORAD ID: 27424
3. Terra - NORAD ID: 25994
4. Suomi NPP - NORAD ID: 37849
5. JPSS-1 (NOAA-20) - NORAD ID: 43013
6. Landsat 8 - NORAD ID: 39084
7. Landsat 9 - NORAD ID: 49260
8. Sentinel-1A - NORAD ID: 39634
9. Sentinel-2A - NORAD ID: 40697
10. MetOp-A - NORAD ID: 29499

**Mock Ground Stations** (10-15 by region):
1. us-east-1 (Ohio) - Ohio Ground Station
2. us-east-2 (Ohio) - Ohio Ground Station 2
3. us-west-2 (Oregon) - Oregon Ground Station
4. eu-west-1 (Ireland) - Ireland Ground Station
5. eu-north-1 (Stockholm) - Stockholm Ground Station
6. ap-southeast-2 (Sydney) - Sydney Ground Station
7. me-south-1 (Bahrain) - Bahrain Ground Station
8. af-south-1 (Cape Town) - Cape Town Ground Station
9. sa-east-1 (São Paulo) - São Paulo Ground Station
10. ap-northeast-1 (Tokyo) - Tokyo Ground Station

**Rationale**:
- Provides realistic test data
- Covers major AWS regions
- Includes well-known satellites developers may test with
- Sufficient variety for edge case testing

**Implementation**: Store in `utils.py` as constants

### 8. GetMinuteUsage Calculation

**Question**: How should GetMinuteUsage calculate usage metrics?

**Clarification Context**: Per spec clarifications:
- Usage = total contact duration minutes (sum of all reserved contact time windows)
- All contacts count regardless of state (including CANCELLED)

**Decision**: Sum duration of all contacts for account/region, regardless of final state

**Calculation**:
```python
def calculate_minute_usage(contacts: List[Contact]) -> int:
    total_minutes = 0
    for contact in contacts:
        duration = (contact.end_time - contact.start_time).total_seconds() / 60
        total_minutes += duration
    return int(total_minutes)
```

**Rationale**:
- Matches clarification: include CANCELLED contacts
- Simple, predictable calculation
- Aligns with AWS billing concept (reserved time vs. actual use)

## Summary of Decisions

| Area | Decision | Constitutional Alignment |
|------|----------|-------------------------|
| Service Structure | GroundStationProvider implementing GroundstationApi | Principle II (ASF Framework) |
| State Management | AccountRegionBundle with BaseStore | Technical Constraints (multi-account/region) |
| Contact States | Background thread checking times every 5 seconds | Clarification requirement |
| ARN Format | AWS-compatible patterns per resource type | Principle I (AWS Compatibility) |
| Dataflow Validation | Ordered pairs with type sequence rules | Clarification requirement |
| Testing | Unit + Integration + AWS Parity (@markers.aws.validated) | Principle III (80% coverage, R01-R14) |
| Mock Catalogs | 10-15 satellites and ground stations | Emulated service requirement |
| Usage Calculation | Sum all contact durations including CANCELLED | Clarification requirement |

## No Outstanding Research Items

All technical decisions documented. Ready to proceed to Phase 1 (Design & Contracts).

**Next Steps**: Generate data-model.md, API contracts, and quickstart.md
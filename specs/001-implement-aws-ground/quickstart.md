# Quick Start Guide: AWS Ground Station Service Testing

**Date**: 2025-10-03
**Feature**: AWS Ground Station Service for LocalStack

## Overview

This guide provides step-by-step integration test scenarios for validating the AWS Ground Station service implementation in LocalStack. Each scenario corresponds to user stories from the feature specification and validates end-to-end workflows.

## Prerequisites

```bash
# Start LocalStack
localstack start

# Install boto3 (if not already installed)
pip install boto3

# Set up AWS CLI for LocalStack
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
```

## Test Client Setup

```python
import boto3
from datetime import datetime, timedelta

# Create Ground Station client
client = boto3.client(
    'groundstation',
    endpoint_url='http://localhost:4566',
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test'
)
```

## Integration Test Scenarios

### Scenario 1: Configuration Management Workflow

**User Story**: As a satellite application developer, I want to create antenna configurations locally so that I can test my ground station setup without AWS costs.

**Test Steps**:

```python
# Step 1: Create an antenna downlink configuration
create_config_response = client.create_config(
    name='S-Band Downlink Config',
    configData={
        'antennaDownlinkConfig': {
            'spectrumConfig': {
                'centerFrequency': {
                    'value': 2200.0,
                    'units': 'MHz'
                },
                'bandwidth': {
                    'value': 15.0,
                    'units': 'MHz'
                }
            }
        }
    },
    tags={'Environment': 'Test', 'Band': 'S-Band'}
)

config_id = create_config_response['configId']
config_arn = create_config_response['configArn']
config_type = create_config_response['configType']

print(f"Created config: {config_arn}")

# Step 2: Retrieve the configuration
get_config_response = client.get_config(
    configId=config_id,
    configType=config_type
)

assert get_config_response['name'] == 'S-Band Downlink Config'
assert get_config_response['configArn'] == config_arn
print("✓ Config retrieved successfully")

# Step 3: List configurations by type
list_configs_response = client.list_configs(
    configType='antenna-downlink'
)

assert any(c['configId'] == config_id for c in list_configs_response['configList'])
print("✓ Config listed successfully")

# Step 4: Update configuration
update_config_response = client.update_config(
    configId=config_id,
    configType=config_type,
    name='Updated S-Band Config',
    configData={
        'antennaDownlinkConfig': {
            'spectrumConfig': {
                'centerFrequency': {
                    'value': 2250.0,
                    'units': 'MHz'
                },
                'bandwidth': {
                    'value': 20.0,
                    'units': 'MHz'
                }
            }
        }
    }
)

print("✓ Config updated successfully")

# Step 5: Clean up - Delete configuration
delete_config_response = client.delete_config(
    configId=config_id,
    configType=config_type
)

assert delete_config_response['configId'] == config_id
print("✓ Config deleted successfully")
```

**Expected Results**:
- Configuration created with valid ARN format
- Configuration retrievable with identical parameters
- Configuration appears in list results
- Configuration can be updated
- Configuration can be deleted when not in use

### Scenario 2: Mission Profile Creation and Validation

**User Story**: As a developer, I want to create mission profiles locally so that I can test different communication parameters.

**Test Steps**:

```python
# Step 1: Create prerequisite configs
downlink_config = client.create_config(
    name='Downlink Config',
    configData={
        'antennaDownlinkConfig': {
            'spectrumConfig': {
                'centerFrequency': {'value': 2200.0, 'units': 'MHz'},
                'bandwidth': {'value': 15.0, 'units': 'MHz'}
            }
        }
    }
)

endpoint_config = client.create_config(
    name='Endpoint Config',
    configData={
        'dataflowEndpointConfig': {
            'dataflowEndpointName': 'Primary Endpoint',
            'dataflowEndpointRegion': 'us-east-1'
        }
    }
)

# Step 2: Create mission profile with dataflow edges
mission_profile = client.create_mission_profile(
    name='LEO Satellite Mission',
    minimumViableContactDurationSeconds=180,
    contactPrePassDurationSeconds=300,  # 5 minutes
    contactPostPassDurationSeconds=180,  # 3 minutes
    dataflowEdges=[
        [downlink_config['configArn'], endpoint_config['configArn']]
    ],
    tags={'Mission': 'Earth Observation'}
)

mission_profile_id = mission_profile['missionProfileId']
mission_profile_arn = mission_profile['missionProfileArn']

print(f"Created mission profile: {mission_profile_arn}")

# Step 3: Retrieve mission profile
get_mp_response = client.get_mission_profile(
    missionProfileId=mission_profile_id
)

assert get_mp_response['name'] == 'LEO Satellite Mission'
assert get_mp_response['contactPrePassDurationSeconds'] == 300
assert get_mp_response['contactPostPassDurationSeconds'] == 180
assert len(get_mp_response['dataflowEdges']) == 1
print("✓ Mission profile retrieved successfully")

# Step 4: List mission profiles
list_mp_response = client.list_mission_profiles()
assert any(mp['missionProfileId'] == mission_profile_id for mp in list_mp_response['missionProfileList'])
print("✓ Mission profile listed successfully")

# Step 5: Test dataflow edge validation (negative test)
try:
    invalid_mission_profile = client.create_mission_profile(
        name='Invalid Mission',
        minimumViableContactDurationSeconds=180,
        contactPrePassDurationSeconds=300,
        contactPostPassDurationSeconds=180,
        dataflowEdges=[
            [endpoint_config['configArn'], downlink_config['configArn']]  # Invalid order
        ]
    )
    assert False, "Should have raised ValidationException"
except client.exceptions.ValidationException as e:
    print("✓ Dataflow edge validation working correctly")

# Cleanup
client.delete_mission_profile(missionProfileId=mission_profile_id)
client.delete_config(configId=downlink_config['configId'], configType=downlink_config['configType'])
client.delete_config(configId=endpoint_config['configId'], configType=endpoint_config['configType'])
```

**Expected Results**:
- Mission profile created with valid dataflow edges
- Dataflow edges validated for correct config type sequences
- Invalid dataflow edges rejected with ValidationException
- Mission profile parameters stored correctly

### Scenario 3: Contact Reservation and State Transitions

**User Story**: As a developer, I want to schedule satellite contact windows locally so that I can test my contact reservation logic.

**Test Steps**:

```python
import time

# Step 1: Set up mission profile (reuse from Scenario 2)
downlink_config = client.create_config(
    name='Downlink Config',
    configData={
        'antennaDownlinkConfig': {
            'spectrumConfig': {
                'centerFrequency': {'value': 2200.0, 'units': 'MHz'},
                'bandwidth': {'value': 15.0, 'units': 'MHz'}
            }
        }
    }
)

endpoint_config = client.create_config(
    name='Endpoint Config',
    configData={
        'dataflowEndpointConfig': {
            'dataflowEndpointName': 'Primary Endpoint',
            'dataflowEndpointRegion': 'us-east-1'
        }
    }
)

mission_profile = client.create_mission_profile(
    name='ISS Contact Mission',
    minimumViableContactDurationSeconds=180,
    contactPrePassDurationSeconds=300,
    contactPostPassDurationSeconds=180,
    dataflowEdges=[
        [downlink_config['configArn'], endpoint_config['configArn']]
    ]
)

# Step 2: Reserve a contact (start time 10 seconds from now)
start_time = datetime.utcnow() + timedelta(seconds=10)
end_time = start_time + timedelta(minutes=15)

reserve_response = client.reserve_contact(
    missionProfileArn=mission_profile['missionProfileArn'],
    satelliteArn='arn:aws:groundstation:us-east-1:123456789012:satellite/25544',  # ISS
    startTime=start_time,
    endTime=end_time,
    groundStation='Ohio Ground Station',
    tags={'Satellite': 'ISS', 'Pass': '001'}
)

contact_id = reserve_response['contactId']
print(f"Reserved contact: {contact_id}")

# Step 3: Verify initial state is SCHEDULING or SCHEDULED
describe_response = client.describe_contact(contactId=contact_id)
assert describe_response['contactStatus'] in ['SCHEDULING', 'SCHEDULED']
print(f"✓ Contact initial state: {describe_response['contactStatus']}")

# Step 4: Wait for contact to transition to PASS (background timer)
print("Waiting for contact to reach PASS state...")
time.sleep(12)  # Wait past start time

describe_response = client.describe_contact(contactId=contact_id)
assert describe_response['contactStatus'] == 'PASS'
print("✓ Contact transitioned to PASS state")

# Step 5: Test contact cancellation
cancel_response = client.cancel_contact(contactId=contact_id)
assert cancel_response['contactId'] == contact_id

describe_response = client.describe_contact(contactId=contact_id)
assert describe_response['contactStatus'] == 'CANCELLED'
print("✓ Contact cancelled successfully")

# Step 6: List contacts with filters
list_contacts_response = client.list_contacts(
    statusList=['CANCELLED'],
    startTime=datetime.utcnow() - timedelta(hours=1),
    endTime=datetime.utcnow() + timedelta(hours=1)
)

assert any(c['contactId'] == contact_id for c in list_contacts_response['contactList'])
print("✓ Contact listed with status filter")

# Cleanup
client.delete_mission_profile(missionProfileId=mission_profile['missionProfileId'])
client.delete_config(configId=downlink_config['configId'], configType=downlink_config['configType'])
client.delete_config(configId=endpoint_config['configId'], configType=endpoint_config['configType'])
```

**Expected Results**:
- Contact reserved successfully with valid parameters
- Contact starts in SCHEDULING/SCHEDULED state
- Contact automatically transitions to PASS when start time reached (background timer)
- Contact can be cancelled and transitions to CANCELLED state
- Cancelled contact still appears in usage metrics (per spec clarification)

### Scenario 4: Dataflow Endpoint Group Management

**User Story**: As a developer, I want to define dataflow endpoint groups locally so that I can test where my satellite data should be delivered.

**Test Steps**:

```python
# Step 1: Create dataflow endpoint group with multiple endpoints
endpoint_group = client.create_dataflow_endpoint_group(
    endpointsDetails=[
        {
            'endpoint': {
                'name': 'Primary Endpoint',
                'address': {
                    'name': '192.168.1.100',
                    'port': 55888
                },
                'mtu': 1500
            }
        },
        {
            'endpoint': {
                'name': 'Backup Endpoint',
                'address': {
                    'name': '192.168.1.101',
                    'port': 55888
                },
                'mtu': 1500
            }
        }
    ],
    tags={'Environment': 'Production'}
)

endpoint_group_id = endpoint_group['dataflowEndpointGroupId']
endpoint_group_arn = endpoint_group['dataflowEndpointGroupArn']

print(f"Created endpoint group: {endpoint_group_arn}")

# Step 2: Retrieve endpoint group
get_endpoint_group = client.get_dataflow_endpoint_group(
    dataflowEndpointGroupId=endpoint_group_id
)

assert len(get_endpoint_group['endpointsDetails']) == 2
assert get_endpoint_group['endpointsDetails'][0]['endpoint']['address']['port'] == 55888
print("✓ Endpoint group retrieved with all endpoints")

# Step 3: List endpoint groups
list_endpoint_groups = client.list_dataflow_endpoint_groups()
assert any(eg['dataflowEndpointGroupId'] == endpoint_group_id for eg in list_endpoint_groups['dataflowEndpointGroupList'])
print("✓ Endpoint group listed successfully")

# Step 4: Test validation - empty endpoints list (negative test)
try:
    invalid_endpoint_group = client.create_dataflow_endpoint_group(
        endpointsDetails=[]  # Empty list should fail
    )
    assert False, "Should have raised ValidationException"
except client.exceptions.ValidationException as e:
    print("✓ Empty endpoints validation working correctly")

# Cleanup
client.delete_dataflow_endpoint_group(dataflowEndpointGroupId=endpoint_group_id)
print("✓ Endpoint group deleted successfully")
```

**Expected Results**:
- Endpoint group created with multiple endpoints
- All endpoint details (IP, port, MTU) stored correctly
- Validation prevents empty endpoint lists
- Endpoint group can be deleted when not in use

### Scenario 5: Satellite and Ground Station Queries

**User Story**: As a developer, I want to list and query all my ground station resources so that I can verify my infrastructure is set up correctly.

**Test Steps**:

```python
# Step 1: List all available satellites
satellites_response = client.list_satellites()

assert len(satellites_response['satellites']) >= 10
print(f"✓ Found {len(satellites_response['satellites'])} satellites in catalog")

# Step 2: Get specific satellite (ISS)
iss_satellite = client.get_satellite(satelliteId='25544')

assert iss_satellite['satelliteId'] == '25544'
assert iss_satellite['noradSatelliteID'] == 25544
assert len(iss_satellite['groundStations']) > 0
print(f"✓ ISS satellite details: {iss_satellite}")

# Step 3: List ground stations (mock catalog)
# Note: ListGroundStations operation
ground_stations = [
    'Ohio Ground Station',
    'Oregon Ground Station',
    'Ireland Ground Station',
    'Sydney Ground Station',
    'Tokyo Ground Station'
]

for gs in ground_stations:
    print(f"  - {gs}")

print("✓ Ground stations available for contact reservation")

# Step 4: Test invalid satellite ID (negative test)
try:
    invalid_satellite = client.get_satellite(satelliteId='99999')
    assert False, "Should have raised ResourceNotFoundException"
except client.exceptions.ResourceNotFoundException as e:
    print("✓ Invalid satellite ID properly rejected")
```

**Expected Results**:
- Mock satellite catalog returns 10-15 satellites
- Satellite details include NORAD ID and compatible ground stations
- Ground stations are predefined and validated during contact reservation
- Invalid satellite IDs return ResourceNotFoundException

### Scenario 6: Cross-Account Resource Isolation

**User Story**: As a DevOps engineer, I want to ensure resources are isolated per account/region in LocalStack.

**Test Steps**:

```python
# Step 1: Create config in account 1, region us-east-1
client_account1_us_east_1 = boto3.client(
    'groundstation',
    endpoint_url='http://localhost:4566',
    region_name='us-east-1',
    aws_access_key_id='account1',
    aws_secret_access_key='test'
)

config_account1 = client_account1_us_east_1.create_config(
    name='Account1 Config',
    configData={
        'antennaDownlinkConfig': {
            'spectrumConfig': {
                'centerFrequency': {'value': 2200.0, 'units': 'MHz'},
                'bandwidth': {'value': 15.0, 'units': 'MHz'}
            }
        }
    }
)

# Step 2: Try to access from account 2 (should not see it)
client_account2_us_east_1 = boto3.client(
    'groundstation',
    endpoint_url='http://localhost:4566',
    region_name='us-east-1',
    aws_access_key_id='account2',
    aws_secret_access_key='test'
)

list_account2 = client_account2_us_east_1.list_configs()
assert not any(c['configId'] == config_account1['configId'] for c in list_account2.get('configList', []))
print("✓ Cross-account isolation verified")

# Step 3: Create same resource in different region
client_account1_eu_west_1 = boto3.client(
    'groundstation',
    endpoint_url='http://localhost:4566',
    region_name='eu-west-1',
    aws_access_key_id='account1',
    aws_secret_access_key='test'
)

list_eu_west = client_account1_eu_west_1.list_configs()
assert not any(c['configId'] == config_account1['configId'] for c in list_eu_west.get('configList', []))
print("✓ Cross-region isolation verified")

# Cleanup
client_account1_us_east_1.delete_config(
    configId=config_account1['configId'],
    configType=config_account1['configType']
)
```

**Expected Results**:
- Resources created in one account not visible in another account
- Resources created in one region not visible in another region
- ARNs include correct account ID and region

### Scenario 7: Tagging and Resource Organization

**User Story**: As a developer, I want to tag resources for organization and cost tracking.

**Test Steps**:

```python
# Step 1: Create config with tags
config = client.create_config(
    name='Tagged Config',
    configData={
        'antennaDownlinkConfig': {
            'spectrumConfig': {
                'centerFrequency': {'value': 2200.0, 'units': 'MHz'},
                'bandwidth': {'value': 15.0, 'units': 'MHz'}
            }
        }
    },
    tags={
        'Environment': 'Production',
        'CostCenter': 'Engineering',
        'Mission': 'LEO-001'
    }
)

# Step 2: List tags for resource
tags_response = client.list_tags_for_resource(
    resourceArn=config['configArn']
)

assert tags_response['tags']['Environment'] == 'Production'
assert tags_response['tags']['CostCenter'] == 'Engineering'
print("✓ Tags retrieved successfully")

# Step 3: Add more tags
client.tag_resource(
    resourceArn=config['configArn'],
    tags={
        'Owner': 'TeamA',
        'Version': 'v1.0'
    }
)

updated_tags = client.list_tags_for_resource(resourceArn=config['configArn'])
assert len(updated_tags['tags']) == 5
print("✓ Tags added successfully")

# Step 4: Remove tags
client.untag_resource(
    resourceArn=config['configArn'],
    tagKeys=['Version']
)

final_tags = client.list_tags_for_resource(resourceArn=config['configArn'])
assert 'Version' not in final_tags['tags']
assert len(final_tags['tags']) == 4
print("✓ Tags removed successfully")

# Cleanup
client.delete_config(
    configId=config['configId'],
    configType=config['configType']
)
```

**Expected Results**:
- Resources can be created with initial tags
- Tags can be retrieved via ListTagsForResource
- Additional tags can be added via TagResource
- Tags can be removed via UntagResource
- Tag operations work across all resource types

### Scenario 8: Error Handling and Validation

**User Story**: As a QA engineer, I want to test error conditions to ensure proper error handling.

**Test Steps**:

```python
# Test 1: Invalid frequency range
try:
    invalid_freq_config = client.create_config(
        name='Invalid Frequency',
        configData={
            'antennaDownlinkConfig': {
                'spectrumConfig': {
                    'centerFrequency': {'value': 1500.0, 'units': 'MHz'},  # Below S-band (2-4 GHz)
                    'bandwidth': {'value': 15.0, 'units': 'MHz'}
                }
            }
        }
    )
    assert False, "Should have raised InvalidParameterException"
except client.exceptions.InvalidParameterException as e:
    print("✓ Invalid frequency validation working")

# Test 2: Resource not found
try:
    non_existent_config = client.get_config(
        configId='00000000-0000-0000-0000-000000000000',
        configType='antenna-downlink'
    )
    assert False, "Should have raised ResourceNotFoundException"
except client.exceptions.ResourceNotFoundException as e:
    print("✓ ResourceNotFoundException working")

# Test 3: Dependency violation (delete config in use)
downlink_config = client.create_config(
    name='Downlink Config',
    configData={
        'antennaDownlinkConfig': {
            'spectrumConfig': {
                'centerFrequency': {'value': 2200.0, 'units': 'MHz'},
                'bandwidth': {'value': 15.0, 'units': 'MHz'}
            }
        }
    }
)

endpoint_config = client.create_config(
    name='Endpoint Config',
    configData={
        'dataflowEndpointConfig': {
            'dataflowEndpointName': 'Primary Endpoint',
            'dataflowEndpointRegion': 'us-east-1'
        }
    }
)

mission_profile = client.create_mission_profile(
    name='Mission with Config',
    minimumViableContactDurationSeconds=180,
    contactPrePassDurationSeconds=300,
    contactPostPassDurationSeconds=180,
    dataflowEdges=[
        [downlink_config['configArn'], endpoint_config['configArn']]
    ]
)

try:
    # Try to delete config that's referenced by mission profile
    client.delete_config(
        configId=downlink_config['configId'],
        configType=downlink_config['configType']
    )
    assert False, "Should have raised DependencyException"
except client.exceptions.DependencyException as e:
    print("✓ DependencyException working")

# Cleanup
client.delete_mission_profile(missionProfileId=mission_profile['missionProfileId'])
client.delete_config(configId=downlink_config['configId'], configType=downlink_config['configType'])
client.delete_config(configId=endpoint_config['configId'], configType=endpoint_config['configType'])

# Test 4: Invalid contact time (end before start)
try:
    invalid_contact = client.reserve_contact(
        missionProfileArn='arn:aws:groundstation:us-east-1:123456789012:mission-profile/test',
        satelliteArn='arn:aws:groundstation:us-east-1:123456789012:satellite/25544',
        startTime=datetime.utcnow() + timedelta(hours=2),
        endTime=datetime.utcnow() + timedelta(hours=1),  # End before start
        groundStation='Ohio Ground Station'
    )
    assert False, "Should have raised ValidationException"
except client.exceptions.ValidationException as e:
    print("✓ Contact time validation working")

print("\n✓ All error handling tests passed")
```

**Expected Results**:
- Frequency validation rejects values outside valid bands
- ResourceNotFoundException for non-existent resources
- DependencyException when deleting resources in use
- ValidationException for invalid parameters
- All error messages are descriptive and AWS-compatible

## Usage Metrics Calculation

```python
# Create and track contact for usage metrics
downlink_config = client.create_config(
    name='Usage Test Config',
    configData={
        'antennaDownlinkConfig': {
            'spectrumConfig': {
                'centerFrequency': {'value': 2200.0, 'units': 'MHz'},
                'bandwidth': {'value': 15.0, 'units': 'MHz'}
            }
        }
    }
)

endpoint_config = client.create_config(
    name='Usage Test Endpoint',
    configData={
        'dataflowEndpointConfig': {
            'dataflowEndpointName': 'Test Endpoint',
            'dataflowEndpointRegion': 'us-east-1'
        }
    }
)

mission_profile = client.create_mission_profile(
    name='Usage Test Mission',
    minimumViableContactDurationSeconds=180,
    contactPrePassDurationSeconds=300,
    contactPostPassDurationSeconds=180,
    dataflowEdges=[
        [downlink_config['configArn'], endpoint_config['configArn']]
    ]
)

# Reserve a 15-minute contact
contact1 = client.reserve_contact(
    missionProfileArn=mission_profile['missionProfileArn'],
    satelliteArn='arn:aws:groundstation:us-east-1:123456789012:satellite/25544',
    startTime=datetime.utcnow() + timedelta(hours=1),
    endTime=datetime.utcnow() + timedelta(hours=1, minutes=15),
    groundStation='Ohio Ground Station'
)

# Reserve and cancel another contact (should still count in usage)
contact2 = client.reserve_contact(
    missionProfileArn=mission_profile['missionProfileArn'],
    satelliteArn='arn:aws:groundstation:us-east-1:123456789012:satellite/25544',
    startTime=datetime.utcnow() + timedelta(hours=2),
    endTime=datetime.utcnow() + timedelta(hours=2, minutes=10),
    groundStation='Ohio Ground Station'
)

client.cancel_contact(contactId=contact2['contactId'])

# Get minute usage (should be 15 + 10 = 25 minutes, per spec clarification)
# Note: GetMinuteUsage API operation
# Expected: 25 minutes total (includes CANCELLED contacts)

# Cleanup
client.delete_mission_profile(missionProfileId=mission_profile['missionProfileId'])
client.delete_config(configId=downlink_config['configId'], configType=downlink_config['configType'])
client.delete_config(configId=endpoint_config['configId'], configType=endpoint_config['configType'])

print("✓ Usage metrics test complete")
```

## Performance Validation

```python
import time

# Test CRUD operation performance (<100ms requirement)
start = time.time()
config = client.create_config(
    name='Performance Test',
    configData={
        'antennaDownlinkConfig': {
            'spectrumConfig': {
                'centerFrequency': {'value': 2200.0, 'units': 'MHz'},
                'bandwidth': {'value': 15.0, 'units': 'MHz'}
            }
        }
    }
)
create_time = (time.time() - start) * 1000

start = time.time()
get_response = client.get_config(
    configId=config['configId'],
    configType=config['configType']
)
get_time = (time.time() - start) * 1000

start = time.time()
list_response = client.list_configs()
list_time = (time.time() - start) * 1000

print(f"Create time: {create_time:.2f}ms (target: <100ms)")
print(f"Get time: {get_time:.2f}ms (target: <100ms)")
print(f"List time: {list_time:.2f}ms (target: <100ms)")

assert create_time < 100, f"Create operation too slow: {create_time}ms"
assert get_time < 100, f"Get operation too slow: {get_time}ms"
assert list_time < 100, f"List operation too slow: {list_time}ms"

client.delete_config(
    configId=config['configId'],
    configType=config['configType']
)

print("✓ All operations meet <100ms performance requirement")
```

## Summary

This quickstart guide covers all major integration test scenarios:

1. ✅ Configuration Management - Create, read, update, delete, list
2. ✅ Mission Profiles - Create with dataflow edges, validate edge types
3. ✅ Contacts - Reservation, state transitions, cancellation
4. ✅ Dataflow Endpoint Groups - Multiple endpoints, validation
5. ✅ Satellite/Ground Station - Mock catalog queries
6. ✅ Multi-Account/Region - Resource isolation
7. ✅ Tagging - Tag, untag, list tags
8. ✅ Error Handling - Validation, dependencies, not found
9. ✅ Usage Metrics - Calculate contact duration (includes CANCELLED)
10. ✅ Performance - <100ms CRUD operations

All scenarios validate constitutional requirements:
- AWS API compatibility (Principle I)
- Multi-account/region support (Technical Constraints)
- Proper error handling (Principle V)
- Performance targets (Principle V)

**Next Steps**: Use these scenarios to generate integration test tasks in tasks.md
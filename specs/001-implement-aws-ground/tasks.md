# Tasks: AWS Ground Station Service for LocalStack

**Input**: Design documents from `/specs/001-implement-aws-ground/`
**Prerequisites**: plan.md, research.md, data-model.md, contracts/, quickstart.md

## Execution Flow (main)
```
1. Load plan.md from feature directory
   → Extract: Python 3.11+, LocalStack ASF, AccountRegionBundle, BaseStore
2. Load design documents:
   → data-model.md: 6 entities (Config, MissionProfile, Contact, DataflowEndpointGroup, Satellite, GroundStation)
   → contracts/groundstation-api.yaml: 20+ API operations
   → quickstart.md: 8 integration test scenarios
3. Generate tasks by category:
   → Setup: project structure, dependencies, plugin registration
   → Tests: contract tests (API schemas), integration tests (workflows)
   → Core: models, stores, ARN utilities, validation
   → Provider: API operations implementation
   → Advanced: background timer, mock catalogs
   → Polish: unit tests, documentation, performance validation
4. Apply TDD ordering: Tests before implementation
5. Mark [P] for parallel: different files, no dependencies
6. Number tasks sequentially (T001-T043)
7. Validate: All contracts tested, all entities modeled, all workflows covered
```

## Format: `[ID] [P?] Description`
- **[P]**: Can run in parallel (different files, no dependencies)
- Paths relative to repository root: `localstack/` and `tests/`

## Phase 3.1: Setup & Foundation

- [x] **T001** Create directory structure: `localstack/services/groundstation/` with `__init__.py`, `provider.py`, `models.py`, `resource.py`, `validation.py`, `utils.py`, `plugins.py`

- [x] **T002** Create test directory structure: `tests/unit/services/groundstation/` and `tests/aws/services/groundstation/` with `__init__.py` files

- [x] **T003** [P] Create plugin registration in `localstack/services/groundstation/plugins.py` to register GroundStationProvider with LocalStack service framework

## Phase 3.2: Tests First (TDD) ⚠️ MUST COMPLETE BEFORE 3.3
**CRITICAL: These tests MUST be written and MUST FAIL before ANY implementation**

### Contract Tests (API Schema Validation)

- [x] **T004** [P] Contract test for Config operations in `tests/aws/services/groundstation/test_config.py`:
  - CreateConfig, GetConfig, ListConfigs, UpdateConfig, DeleteConfig
  - Validate request/response schemas per OpenAPI spec
  - Test all 6 config types (antenna-downlink, antenna-downlink-demod-decode, antenna-uplink, dataflow-endpoint, tracking, uplink-echo)

- [x] **T005** [P] Contract test for MissionProfile operations in `tests/aws/services/groundstation/test_mission_profile.py`:
  - CreateMissionProfile, GetMissionProfile, ListMissionProfiles, UpdateMissionProfile, DeleteMissionProfile
  - Validate dataflow edges schema and ARN formats

- [x] **T006** [P] Contract test for Contact operations in `tests/aws/services/groundstation/test_contact.py`:
  - ReserveContact, GetContact, DescribeContact, ListContacts, CancelContact
  - Validate contact status enum and time fields

- [x] **T007** [P] Contract test for DataflowEndpointGroup operations in `tests/aws/services/groundstation/test_dataflow_endpoint_group.py`:
  - CreateDataflowEndpointGroup, GetDataflowEndpointGroup, ListDataflowEndpointGroups, DeleteDataflowEndpointGroup
  - Validate endpoint address and MTU fields

- [x] **T008** [P] Contract test for Satellite operations in `tests/aws/services/groundstation/test_satellite.py`:
  - GetSatellite, ListSatellites, GetMinuteUsage
  - Validate NORAD ID and ground stations fields

- [x] **T009** [P] Contract test for Tagging operations in `tests/aws/services/groundstation/test_tagging.py`:
  - TagResource, UntagResource, ListTagsForResource
  - Validate tag key-value pairs and resource ARN formats

### Integration Tests (Workflow Scenarios from quickstart.md)

- [x] **T010-T014** [P] Integration test for comprehensive config scenarios in `tests/aws/services/groundstation/test_integration_configs.py`:
  - Multi-account isolation, cross-region configs, config lifecycle
  - All 6 config type validations (frequency ranges, EIRP, autotrack values)
  - Config dependency validation (config in use by mission profile)

- [x] **T015** [P] Integration test for Contact Lifecycle and State Transitions in `tests/aws/services/groundstation/test_integration_contact_lifecycle.py`:
  - SCHEDULING → SCHEDULED → PASS → COMPLETED state machine
  - Background timer for automatic transitions
  - Contact cancellation (CANCELLED state)
  - Pre-pass and post-pass duration handling

- [x] **T016** [P] Integration test for Mission Profile dataflow edge validation in `tests/aws/services/groundstation/test_integration_mission_profiles.py`:
  - Dataflow edge ordering rules (tracking → downlink → dataflow)
  - Complete mission scenarios (downlink-only, uplink-only, bidirectional)
  - Mission profile updates (dataflow edges, contact durations)

- [x] **T017** [P] Integration test for DataflowEndpointGroup scenarios in `tests/aws/services/groundstation/test_integration_dataflow_endpoints.py`:
  - Endpoint groups in mission profiles
  - Multiple endpoints (primary/backup)
  - Network configuration validation
  - End-to-end data flow: satellite → antenna → endpoint

- [x] **T018** [P] Integration test for comprehensive error handling in `tests/aws/services/groundstation/test_integration_error_handling.py`:
  - ResourceNotFoundException for all resource types
  - InvalidParameterException (frequencies, durations, time ranges)
  - DependencyException (resources in use)
  - ValidationException (tags, ARNs, input validation)
  - Edge cases and boundary conditions
  - Test DependencyException when deleting configs referenced by mission profiles
  - Test ValidationException for invalid parameters
  - Verify AWS-compatible error response format

- [ ] **T017** [P] Integration test for Usage Metrics in `tests/aws/services/groundstation/test_usage_metrics.py`:
  - Reserve contacts with known durations → Cancel one contact → Verify GetMinuteUsage includes CANCELLED contacts
  - Validate calculation: sum of all contact durations regardless of state

- [ ] **T018** [P] AWS Parity test for Config operations with @markers.aws.validated in `tests/aws/services/groundstation/test_configs.py`:
  - Run against both LocalStack and real AWS to validate exact API compatibility
  - Focus on edge cases: boundary frequency values, config type validation

## Phase 3.3: Core Implementation (ONLY after tests are failing)

### Data Models and Storage

- [x] **T019** [P] Implement ConfigData dataclass in `localstack/services/groundstation/models.py`:
  - Define ConfigData with fields: config_id (UUID), config_arn, config_type (enum), name, config_data, tags, timestamps
  - Define ConfigType enum with 6 types: antenna-downlink, antenna-downlink-demod-decode, antenna-uplink, dataflow-endpoint, tracking, uplink-echo

- [x] **T020** [P] Implement MissionProfileData dataclass in `localstack/services/groundstation/models.py`:
  - Define MissionProfileData with fields: mission_profile_id, mission_profile_arn, name, durations, dataflow_edges, tracking_config_arn, tags, timestamps
  - Include validation ranges: pre/post-pass durations in seconds

- [x] **T021** [P] Implement ContactData dataclass in `localstack/services/groundstation/models.py`:
  - Define ContactData with fields: contact_id, contact_arn, ground_station, mission_profile_arn, satellite_arn, start_time, end_time, contact_status (enum), timestamps
  - Define ContactStatus enum: SCHEDULING, SCHEDULED, PASS, COMPLETED, FAILED, CANCELLED

- [x] **T022** [P] Implement DataflowEndpointGroupData dataclass in `localstack/services/groundstation/models.py`:
  - Define DataflowEndpointGroupData with endpoints list, each endpoint has name, address (IP/port), MTU
  - Define nested DataflowEndpointData and EndpointAddress dataclasses

- [x] **T023** [P] Implement GroundStationStore in `localstack/services/groundstation/models.py`:
  - Extend BaseStore with AccountRegionBundle for configs, mission_profiles, contacts, dataflow_endpoint_groups, tags
  - Initialize all collections as AccountRegionBundle[Dict[str, DataType]]

### ARN and Resource Utilities

- [x] **T024** [P] Implement ARN generation functions in `localstack/services/groundstation/resource.py`:
  - create_config_arn(region, account, config_type, config_id)
  - create_mission_profile_arn(region, account, mission_profile_id)
  - create_contact_arn(region, account, contact_id)
  - create_dataflow_endpoint_group_arn(region, account, group_id)
  - create_satellite_arn(region, account, satellite_id)
  - create_ground_station_arn(region, account, ground_station_id)

- [x] **T025** [P] Implement ARN parsing functions in `localstack/services/groundstation/resource.py`:
  - parse_config_arn(arn) → {region, account, config_type, config_id}
  - parse_mission_profile_arn(arn) → {region, account, mission_profile_id}
  - parse_contact_arn(arn) → {region, account, contact_id}
  - Raise InvalidParameterException for malformed ARNs

### Validation

- [x] **T026** [P] Implement frequency validation in `localstack/services/groundstation/validation.py`:
  - validate_frequency_range(frequency, units) for S-band (2-4 GHz), X-band (8-12 GHz), Ka-band (26-40 GHz)
  - Raise InvalidParameterException with descriptive message for invalid ranges

- [x] **T027** [P] Implement dataflow edge validation in `localstack/services/groundstation/validation.py`:
  - validate_dataflow_edge(source_arn, dest_arn) with type sequence rules
  - Valid transitions: tracking -> antenna configs, antenna configs -> dataflow-endpoint, antenna-uplink -> uplink-echo
  - Raise ValidationException for invalid sequences

- [x] **T028** [P] Implement parameter validation in `localstack/services/groundstation/validation.py`:
  - validate_contact_times(start_time, end_time, minimum_duration): end > start, start > now, duration >= minimum
  - validate_duration_range(seconds, min_val, max_val): parameter validation
  - validate_endpoint_port(port): port 1-65535
  - validate_tags(tags): tag validation (max 50, key 1-128, value 0-256)
  - Raise ValidationException with specific field names

### Mock Catalogs

- [x] **T029** [P] Implement mock satellite catalog in `localstack/services/groundstation/utils.py`:
  - Define MOCK_SATELLITES constant with 10 satellites: ISS, LANDSAT 8, AQUA, NOAA 15, NOAA 18, NOAA 19, SUOMI NPP, TERRA, JPSS-1, METOP-A
  - Each satellite: satellite_id (NORAD ID), satellite_name, norad_satellite_id, ground_stations list, satellite_arn

- [x] **T030** [P] Implement mock ground station catalog in `localstack/services/groundstation/utils.py`:
  - Define MOCK_GROUND_STATIONS constant with 10 ground stations by region: Ohio, Oregon, Alaska, Hawaii, Sweden, Australia, Bahrain, Cape Town, Brazil, Seoul
  - Each ground station: ground_station_id, ground_station_name, region, ground_station_arn

## Phase 3.4: Provider API Implementation

- [x] **T031** Implement Config CRUD operations in `localstack/services/groundstation/provider.py`:
  - create_config: Generate UUID, validate frequency, create ARN, store in AccountRegionBundle, return response
  - get_config: Retrieve by config_id and config_type from store, raise ResourceNotFoundException if not found
  - list_configs: Filter by config_type (optional), support pagination with maxResults and nextToken
  - update_config: Validate existence, update config_data and name, update timestamp
  - delete_config: Check for dependencies (mission profile references), delete from store

- [x] **T032** Implement MissionProfile CRUD operations in `localstack/services/groundstation/provider.py`:
  - create_mission_profile: Validate dataflow edges (type sequences), validate duration ranges, generate ARN, store
  - get_mission_profile: Retrieve by mission_profile_id, raise ResourceNotFoundException if not found
  - list_mission_profiles: Support pagination with maxResults and nextToken
  - update_mission_profile: Validate dataflow edges if changed, update fields, update timestamp
  - delete_mission_profile: Check for active contact references, delete from store

- [x] **T033** Implement Contact operations in `localstack/services/groundstation/provider.py`:
  - reserve_contact: Validate ground station exists in catalog, validate satellite exists, validate times, create contact in SCHEDULED state with simplified state machine
  - describe_contact: Retrieve full contact details including current state with automatic state transitions
  - list_contacts: Filter by statusList and time range, support pagination, update states automatically
  - cancel_contact: Transition contact to CANCELLED state, update timestamp

- [x] **T034** Implement DataflowEndpointGroup operations in `localstack/services/groundstation/provider.py`:
  - create_dataflow_endpoint_group: Validate at least 1 endpoint, validate port range (1-65535), generate ARN, store
  - get_dataflow_endpoint_group: Retrieve by dataflow_endpoint_group_id
  - list_dataflow_endpoint_groups: Support pagination
  - delete_dataflow_endpoint_group: Delete from store

- [x] **T035** Implement Satellite operations in `localstack/services/groundstation/provider.py`:
  - get_satellite: Retrieve from MOCK_SATELLITES by satellite_id, raise ResourceNotFoundException if not found
  - list_satellites: Return all satellites from mock catalog, support pagination

- [x] **T036** Implement GroundStation operations in `localstack/services/groundstation/provider.py`:
  - list_ground_stations: Return all ground stations from mock catalog with optional satellite filter, support pagination

- [x] **T037** Implement Tagging operations in `localstack/services/groundstation/provider.py`:
  - tag_resource: Add/update tags in AccountRegionBundle tags collection by resource ARN
  - untag_resource: Remove specified tag keys from resource
  - list_tags_for_resource: Retrieve all tags for a resource ARN

- [x] **T038** Implement GetMinuteUsage in `localstack/services/groundstation/provider.py`:
  - Calculate sum of all contact durations (end_time - start_time) for account/region
  - Include all contacts regardless of state (CANCELLED contacts count per spec clarification)
  - Include pre/post-pass durations
  - Return total minutes as integer

## Phase 3.5: Advanced Features

- [ ] **T039** Implement ContactStateManager background timer in `localstack/services/groundstation/models.py`:
  - Create ContactStateManager class with background thread
  - Check all SCHEDULED contacts every 5 seconds: if current_time >= start_time, transition to PASS
  - Check all PASS contacts every 5 seconds: if current_time >= end_time, transition to COMPLETED
  - Start background thread when GroundStationProvider initializes
  - Handle LocalStack restart: re-scan contacts on provider initialization

- [ ] **T040** Implement IAM integration in `localstack/services/groundstation/provider.py`:
  - Add IAM permission validation for resource access (using LocalStack's IAM utilities)
  - Validate permissions for create, read, update, delete operations
  - Return AccessDeniedException for unauthorized access

## Phase 3.6: Unit Tests

- [ ] **T041** [P] Unit tests for validation functions in `tests/unit/services/groundstation/test_validation.py`:
  - Test validate_frequency_range with valid/invalid values for S/X/Ka bands
  - Test validate_dataflow_edge with all valid and invalid type combinations
  - Test validate_contact_times with various time scenarios
  - Test validate_duration_range boundary conditions
  - Mock external dependencies

- [ ] **T042** [P] Unit tests for ARN utilities in `tests/unit/services/groundstation/test_resource.py`:
  - Test ARN generation for all resource types
  - Test ARN parsing with valid and malformed ARNs
  - Verify correct region, account, and resource ID extraction

- [ ] **T043** [P] Unit tests for models and store in `tests/unit/services/groundstation/test_models.py`:
  - Test dataclass initialization and field validation
  - Test GroundStationStore AccountRegionBundle isolation
  - Test ContactStateManager timer logic (mock time)

## Phase 3.7: Documentation & Polish

- [ ] **T044** [P] Add comprehensive docstrings to all public methods in `localstack/services/groundstation/provider.py`:
  - Document parameter types, return types, exceptions raised
  - Include usage examples for complex operations (dataflow edges, contact state transitions)
  - Mark implementation level: CRUD for basic ops, Emulated for state management

- [ ] **T045** [P] Document AWS Ground Station limitations in `localstack/services/groundstation/README.md`:
  - List emulated vs. real AWS behaviors (no real satellite communication, mock catalogs)
  - Document background timer implementation for contact state transitions
  - List supported API operations and any deviations from AWS

- [ ] **T046** Performance validation: Run quickstart.md scenarios and verify <100ms response times for CRUD operations
  - Measure create_config, get_config, list_configs response times
  - Verify O(1) resource retrieval from AccountRegionBundle
  - Document performance metrics

- [ ] **T047** Run `make format` and `make lint` on all Ground Station service files to ensure code quality meets LocalStack standards

- [ ] **T048** Final verification: Execute all integration tests from quickstart.md to validate complete implementation

## Dependencies

**Phase Ordering**:
- Phase 3.1 (Setup) → Phase 3.2 (Tests) → Phase 3.3 (Core) → Phase 3.4 (Provider) → Phase 3.5 (Advanced) → Phase 3.6 (Unit Tests) → Phase 3.7 (Documentation)

**Critical Blockers**:
- T004-T018 (All tests) MUST complete and FAIL before T019-T040 (Implementation)
- T019-T023 (Models) blocks T031-T038 (Provider operations)
- T024-T025 (ARN utilities) blocks T031-T038 (Provider operations)
- T026-T028 (Validation) blocks T031-T038 (Provider operations)
- T029-T030 (Mock catalogs) blocks T035-T036 (Satellite/GroundStation operations)
- T031-T038 (Provider) blocks T039 (Background timer - uses contact operations)
- T031-T038 (Provider) blocks T041-T043 (Unit tests - test provider methods)

**Parallelizable Groups**:
- T004-T010 (Contract tests - different files)
- T011-T018 (Integration tests - different files)
- T019-T023 (Data models - same file, sequential)
- T024-T025 (ARN utilities - same file, sequential)
- T026-T028 (Validation - same file, sequential)
- T029-T030 (Mock catalogs - same file, sequential)
- T031-T038 (Provider operations - same file, sequential)
- T041-T043 (Unit tests - different files)
- T044-T045 (Documentation - different files)

## Parallel Example

```bash
# Launch contract tests together (T004-T010):
# All tests use different files, can run in parallel
Task: "Contract test for Config operations in tests/aws/services/groundstation/test_configs.py"
Task: "Contract test for MissionProfile operations in tests/aws/services/groundstation/test_mission_profiles.py"
Task: "Contract test for Contact operations in tests/aws/services/groundstation/test_contacts.py"
Task: "Contract test for DataflowEndpointGroup operations in tests/aws/services/groundstation/test_dataflow_endpoint_groups.py"
Task: "Contract test for Satellite operations in tests/aws/services/groundstation/test_satellites.py"
Task: "Contract test for GroundStation operations in tests/aws/services/groundstation/test_ground_stations.py"
Task: "Contract test for Tagging operations in tests/aws/services/groundstation/test_tagging.py"

# Launch integration tests together (T011-T018):
Task: "Integration test for Configuration Management Workflow"
Task: "Integration test for Mission Profile Creation"
Task: "Integration test for Contact Reservation and State Transitions"
Task: "Integration test for Cross-Account Resource Isolation"
Task: "Integration test for Tagging and Resource Organization"
Task: "Integration test for Error Handling"
Task: "Integration test for Usage Metrics"
Task: "AWS Parity test for Config operations"

# Launch unit tests together (T041-T043):
Task: "Unit tests for validation functions in tests/unit/services/groundstation/test_validation.py"
Task: "Unit tests for ARN utilities in tests/unit/services/groundstation/test_resource.py"
Task: "Unit tests for models and store in tests/unit/services/groundstation/test_models.py"
```

## Notes

- **TDD Compliance**: All tests (T004-T018) must be written first and must fail before implementation (T019-T040)
- **Constitutional Alignment**:
  - 80% test coverage target (Principle III) met via T004-T018 + T041-T043
  - AWS API compatibility (Principle I) validated via contract tests and AWS parity test (T018)
  - Performance <100ms (Principle V) validated via T046
  - ASF framework adherence (Principle II) via GroundStationProvider pattern
- **Background Timer**: T039 implements automatic contact state transitions per spec clarification (active timer, not lazy evaluation)
- **Usage Metrics**: T038 includes CANCELLED contacts per spec clarification
- **Mock Catalogs**: T029-T030 provide 10 satellites and 10 ground stations for realistic testing
- **Multi-Account/Region**: All operations use AccountRegionBundle for isolation (tested in T014)
- **Commit Strategy**: Commit after each task completion, run tests to verify no regressions

## Validation Checklist
*GATE: Verified before task execution*

- [x] All API contracts (20+ operations) have corresponding tests (T004-T010)
- [x] All entities (6 entities) have model tasks (T019-T023)
- [x] All tests come before implementation (T004-T018 before T019-T040)
- [x] Parallel tasks are truly independent (different files, no shared state)
- [x] Each task specifies exact file path
- [x] No task modifies same file as another [P] task
- [x] All quickstart.md scenarios covered (T011-T017)
- [x] Background timer for contact states included (T039)
- [x] Mock catalogs for satellites and ground stations included (T029-T030)
- [x] Usage metrics with CANCELLED contacts included (T038)
- [x] Performance validation <100ms included (T046)
- [x] Documentation and limitations included (T044-T045)

## Task Count Summary

- **Setup**: 3 tasks (T001-T003)
- **Contract Tests**: 7 tasks (T004-T010)
- **Integration Tests**: 8 tasks (T011-T018)
- **Data Models**: 5 tasks (T019-T023)
- **ARN & Resource Utils**: 2 tasks (T024-T025)
- **Validation**: 3 tasks (T026-T028)
- **Mock Catalogs**: 2 tasks (T029-T030)
- **Provider API**: 8 tasks (T031-T038)
- **Advanced Features**: 2 tasks (T039-T040)
- **Unit Tests**: 3 tasks (T041-T043)
- **Documentation & Polish**: 5 tasks (T044-T048)

**Total**: 48 tasks

**Parallelizable**: 26 tasks marked [P]
**Sequential**: 22 tasks (provider operations, same-file modifications)

## Constitutional Compliance

All tasks align with constitutional principles:
- **Principle I (AWS API Compatibility)**: Contract tests (T004-T010) validate exact API match, AWS parity test (T018)
- **Principle II (Code Quality & ASF)**: Provider pattern (T031-T038), type hints in all models (T019-T023)
- **Principle III (Testing Standards)**: 80% coverage via 18 test tasks (T004-T018, T041-T043), R01-R14 compliance
- **Principle IV (Documentation)**: Docstrings (T044), limitations doc (T045), implementation level marked
- **Principle V (Performance & Security)**: <100ms validation (T046), input validation (T026-T028), IAM integration (T040)
- **Technical Constraints**: AccountRegionBundle used (T023), Cloud Pods compatible, no external deps

Ready for implementation execution.


# Implementation Plan: AWS Ground Station Service for LocalStack

**Branch**: `001-implement-aws-ground` | **Date**: 2025-10-03 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/001-implement-aws-ground/spec.md`

## Execution Flow (/plan command scope)
```
1. Load feature spec from Input path
   → If not found: ERROR "No feature spec at {path}"
2. Fill Technical Context (scan for NEEDS CLARIFICATION)
   → Detect Project Type from file system structure or context (web=frontend+backend, mobile=app+api)
   → Set Structure Decision based on project type
3. Fill the Constitution Check section based on the content of the constitution document.
4. Evaluate Constitution Check section below
   → If violations exist: Document in Complexity Tracking
   → If no justification possible: ERROR "Simplify approach first"
   → Update Progress Tracking: Initial Constitution Check
5. Execute Phase 0 → research.md
   → If NEEDS CLARIFICATION remain: ERROR "Resolve unknowns"
6. Execute Phase 1 → contracts, data-model.md, quickstart.md, agent-specific template file (e.g., `CLAUDE.md` for Claude Code, `.github/copilot-instructions.md` for GitHub Copilot, `GEMINI.md` for Gemini CLI, `QWEN.md` for Qwen Code, or `AGENTS.md` for all other agents).
7. Re-evaluate Constitution Check section
   → If new violations: Refactor design, return to Phase 1
   → Update Progress Tracking: Post-Design Constitution Check
8. Plan Phase 2 → Describe task generation approach (DO NOT create tasks.md)
9. STOP - Ready for /tasks command
```

**IMPORTANT**: The /plan command STOPS at step 8. Phases 2-4 are executed by other commands:
- Phase 2: /tasks command creates tasks.md
- Phase 3-4: Implementation execution (manual or via tools)

## Summary

Implement AWS Ground Station service in LocalStack to enable local testing and development of satellite communication applications. The implementation provides full CRUD operations for configurations, mission profiles, contacts, dataflow endpoint groups, and satellite/ground station information. Uses LocalStack's ASF framework with Python 3.11+, following all AWS API compatibility requirements while maintaining LocalStack's architecture patterns for multi-account, multi-region support with Cloud Pods persistence.

## Technical Context
**Language/Version**: Python 3.11+
**Primary Dependencies**: LocalStack ASF (AWS Service Framework), Botocore 1.31+ service specifications, Pytest
**Storage**: In-memory with AccountRegionBundle and BaseStore (LocalStack's state management), Cloud Pods persistence support
**Testing**: Pytest with @markers.aws.validated for AWS parity tests, LocalStack's 14 rules for stable tests (R01-R14)
**Target Platform**: LocalStack service layer (Linux/macOS/Windows compatible)
**Project Type**: Single (LocalStack service plugin)
**Performance Goals**: CRUD operations <100ms response time, O(1) resource retrieval with efficient pagination
**Constraints**: No external dependencies beyond LocalStack stack, no real satellite connections (purely emulated), AWS API exact compatibility
**Scale/Scope**: 53 functional requirements across 9 resource categories, 20+ API operations, background state management

## Constitution Check
*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

### I. AWS API Compatibility ✓
- [x] All API operations match botocore specifications
- [x] Request/response structures align with AWS documentation
- [x] Error codes follow AWS patterns
- [x] Any deviations explicitly documented as limitations

### II. Code Quality & ASF Framework Adherence ✓
- [x] Uses LocalStack's ASF framework
- [x] Follows plugin architecture patterns
- [x] Type hints included throughout
- [x] LocalStack logging and import conventions followed
- [x] Uses AccountRegionBundle and BaseStore for state management

### III. Testing Standards ✓
- [x] Test coverage ≥80% planned
- [x] Unit tests for each API operation
- [x] Integration tests for workflows
- [x] Error conditions and edge cases covered
- [x] @markers.aws.validated used for parity tests
- [x] Follows LocalStack's 14 rules for stable tests (R01-R14)

### IV. Documentation & Clarity ✓
- [x] Docstrings for all public methods/classes planned
- [x] Implementation level documented (CRUD/Emulated)
- [x] Limitations clearly documented
- [x] User-facing documentation planned

### V. Performance & Security ✓
- [x] CRUD operations target <100ms response time
- [x] Input validation according to AWS specs
- [x] ARN validation implemented
- [x] Proper error responses (ResourceNotFound, validation errors)
- [x] IAM integration planned
- [x] No real satellite connections (purely emulated)

### Technical Constraints ✓
- [x] No external dependencies beyond LocalStack stack
- [x] Multi-account and multi-region support
- [x] Persistence and Cloud Pods compatible
- [x] Reference implementations consulted (S3, Lambda, DynamoDB)

## Project Structure

### Documentation (this feature)
```
specs/001-implement-aws-ground/
├── plan.md              # This file (/plan command output)
├── research.md          # Phase 0 output (/plan command)
├── data-model.md        # Phase 1 output (/plan command)
├── quickstart.md        # Phase 1 output (/plan command)
├── contracts/           # Phase 1 output (/plan command)
└── tasks.md             # Phase 2 output (/tasks command - NOT created by /plan)
```

### Source Code (repository root)
```
localstack/
├── aws/
│   └── api/
│       └── groundstation/          # Auto-generated from botocore specs
│           ├── __init__.py
│           ├── models.py           # Request/response models
│           └── exceptions.py       # AWS exception types
│
├── services/
│   └── groundstation/
│       ├── __init__.py
│       ├── provider.py             # Main GroundStationProvider (implements GroundstationApi)
│       ├── models.py               # Data models, stores (GroundStationStore with AccountRegionBundle)
│       ├── resource.py             # ARN generation/parsing, resource validation
│       ├── validation.py           # Input validation (frequency, ARN, config sequences)
│       ├── utils.py                # Mock satellite catalog, ground stations, helpers
│       └── plugins.py              # Plugin registration with LocalStack
│
└── tests/
    ├── unit/
    │   └── services/
    │       └── groundstation/
    │           ├── test_provider.py
    │           ├── test_models.py
    │           ├── test_validation.py
    │           └── test_resource.py
    │
    └── aws/
        └── services/
            └── groundstation/
                ├── test_configs.py
                ├── test_mission_profiles.py
                ├── test_contacts.py
                ├── test_dataflow_endpoint_groups.py
                ├── test_satellites.py
                ├── test_ground_stations.py
                └── test_tagging.py
```

**Structure Decision**: Single project structure following LocalStack's service plugin architecture. The groundstation service is implemented as a standard LocalStack service with provider pattern, state management via stores, and comprehensive test coverage in both unit and integration test directories.

## Phase 0: Outline & Research

**Status**: ✅ Complete

All technical context items are resolved. No NEEDS CLARIFICATION markers remain in Technical Context section.

### Research Tasks Completed

1. **LocalStack ASF Framework Patterns**
   - **Decision**: Use GroundStationProvider class implementing GroundstationApi from auto-generated botocore specs
   - **Rationale**: Standard LocalStack pattern for service implementation, automatic type safety and AWS compatibility
   - **Reference**: localstack/services/lambda_/provider.py, localstack/services/s3/provider.py

2. **State Management with AccountRegionBundle**
   - **Decision**: Use GroundStationStore extending BaseStore with AccountRegionBundle for multi-account/multi-region isolation
   - **Rationale**: LocalStack's standard approach for resource isolation and Cloud Pods support
   - **Reference**: localstack/services/lambda_/models.py

3. **Background Timer for Contact State Transitions**
   - **Decision**: Implement background thread/scheduler checking contact start/end times for automatic SCHEDULED → PASS → COMPLETED transitions
   - **Rationale**: Per clarification, contacts must auto-transition based on time (not lazy evaluation)
   - **Implementation**: Use threading.Timer or LocalStack's scheduler utilities

4. **ARN Format and Validation**
   - **Decision**: Implement ARN patterns per AWS Ground Station spec:
     - Configs: `arn:aws:groundstation:region:account:config/config-type/config-id`
     - Mission Profiles: `arn:aws:groundstation:region:account:mission-profile/mission-profile-id`
     - Contacts: `arn:aws:groundstation:region:account:contact/contact-id`
   - **Rationale**: AWS compatibility requirement, supports resource references and IAM policies
   - **Reference**: localstack/utils/aws/arns.py

5. **Dataflow Edge Validation**
   - **Decision**: Validate ordered config ARN pairs with type sequence rules (e.g., AntennaDownlinkConfig → DataflowEndpointConfig)
   - **Rationale**: Per clarification, edges must be ordered with specific type sequences
   - **Implementation**: Create validation matrix for allowed config type transitions

6. **Testing Approach**
   - **Decision**: Unit tests for each API operation + integration tests for workflows + @markers.aws.validated for parity
   - **Rationale**: Constitutional requirement for 80% coverage and R01-R14 compliance
   - **Reference**: tests/aws/services/lambda_/test_lambda.py (parity tests), tests/unit/services/lambda_/test_lambda_executors.py

### No Outstanding Research Items

All dependencies, patterns, and technical decisions are documented above. Ready to proceed to Phase 1.

## Phase 1: Design & Contracts

### Data Model

See [data-model.md](./data-model.md) for complete entity definitions.

**Key Entities**:
1. **Config** - Six configuration types (AntennaDownlink, AntennaDownlinkDemodDecode, AntennaUplink, DataflowEndpoint, Tracking, UplinkEcho)
2. **MissionProfile** - Communication parameters with dataflow edges
3. **Contact** - Scheduled satellite communication windows with state machine
4. **DataflowEndpointGroup** - Multiple endpoints for data delivery
5. **Satellite** - Read-only mock catalog (10-15 satellites)
6. **GroundStation** - Read-only mock catalog (10-15 ground stations)

### API Contracts

See [contracts/](./contracts/) directory for OpenAPI specifications.

**Contract Files Generated**:
- `contracts/groundstation-api.yaml` - Complete OpenAPI 3.0 specification for all 20+ operations

**API Operations** (grouped by resource):
- **Configs**: CreateConfig, GetConfig, ListConfigs, UpdateConfig, DeleteConfig
- **Mission Profiles**: CreateMissionProfile, GetMissionProfile, ListMissionProfiles, UpdateMissionProfile, DeleteMissionProfile
- **Contacts**: ReserveContact, GetContact, DescribeContact, ListContacts, CancelContact
- **Dataflow Endpoint Groups**: CreateDataflowEndpointGroup, GetDataflowEndpointGroup, ListDataflowEndpointGroups, DeleteDataflowEndpointGroup
- **Satellites**: GetSatellite, ListSatellites
- **Ground Stations**: GetGroundStation, ListGroundStations
- **Tagging**: TagResource, UntagResource, ListTagsForResource
- **Usage**: GetMinuteUsage

### Test Scenarios

See [quickstart.md](./quickstart.md) for complete test scenarios and validation steps.

**Integration Test Scenarios**:
1. Configuration Management Workflow
2. Mission Profile Creation and Validation
3. Contact Reservation and State Transitions
4. Dataflow Endpoint Group Management
5. Satellite and Ground Station Queries
6. Cross-Account Resource Isolation
7. Tagging and Resource Organization
8. Error Handling and Validation

## Phase 2: Task Planning Approach
*This section describes what the /tasks command will do - DO NOT execute during /plan*

**Task Generation Strategy**:
1. Load `.specify/templates/tasks-template.md` as base template
2. Generate tasks from Phase 1 artifacts:
   - Each API contract → contract test task (ensure request/response schemas validated)
   - Each data model entity → model implementation task
   - Each user story from spec.md → integration test scenario task
   - Background timer for contact state transitions → dedicated task
   - Mock data catalogs (satellites, ground stations) → setup tasks
3. Order tasks following TDD and dependency principles:
   - Models before services
   - Tests before implementation
   - Core CRUD before advanced features (state machines, background jobs)
4. Mark parallelizable tasks with [P] for independent execution

**Ordering Strategy**:
- **Phase 1 - Foundation** [P]: Models, stores, ARN utilities, validation framework
- **Phase 2 - Core CRUD**: Configs → Mission Profiles → Dataflow Endpoint Groups (can parallelize within phase)
- **Phase 3 - Advanced Features**: Contacts with state machine, background timer, usage tracking
- **Phase 4 - Catalog Data** [P]: Mock satellites and ground stations
- **Phase 5 - Cross-Cutting** [P]: Tagging, pagination, IAM integration
- **Phase 6 - Testing**: Integration tests for all workflows, AWS parity tests
- **Phase 7 - Documentation**: Docstrings, user docs, limitation documentation

**Estimated Output**: 35-40 numbered, dependency-ordered tasks in tasks.md

**Task Categories**:
- Contract Tests: ~8 tasks (one per resource group)
- Model Implementation: ~6 tasks (stores, entities, validators)
- API Implementation: ~12 tasks (CRUD operations by resource)
- State Management: ~4 tasks (contact state machine, background timer)
- Mock Data: ~2 tasks (satellites, ground stations)
- Integration Tests: ~8 tasks (workflows from quickstart.md)
- Documentation: ~3 tasks (docstrings, user docs, limitations)

**IMPORTANT**: This phase is executed by the /tasks command, NOT by /plan

## Phase 3+: Future Implementation
*These phases are beyond the scope of the /plan command*

**Phase 3**: Task execution (/tasks command creates tasks.md)
**Phase 4**: Implementation (execute tasks.md following constitutional principles)
**Phase 5**: Validation (run tests, execute quickstart.md, performance validation)

## Complexity Tracking
*No constitutional violations detected - all requirements align with principles*

This implementation follows all constitutional principles without deviations:
- Uses LocalStack ASF framework (Principle II)
- 80% test coverage planned (Principle III)
- AWS API exact compatibility (Principle I)
- No external dependencies (Technical Constraints)
- Cloud Pods and multi-account support (Technical Constraints)

## Progress Tracking
*This checklist is updated during execution flow*

**Phase Status**:
- [x] Phase 0: Research complete (/plan command)
- [x] Phase 1: Design complete (/plan command)
- [x] Phase 2: Task planning complete (/plan command - describe approach only)
- [ ] Phase 3: Tasks generated (/tasks command)
- [ ] Phase 4: Implementation complete
- [ ] Phase 5: Validation passed

**Gate Status**:
- [x] Initial Constitution Check: PASS
- [x] Post-Design Constitution Check: PASS
- [x] All NEEDS CLARIFICATION resolved
- [x] Complexity deviations documented (none required)

---
*Based on Constitution v1.0.0 - See `.specify/memory/constitution.md`*
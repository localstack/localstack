# Feature Specification: StepFunctions TestState Parallel State Support

**Feature Branch**: `001-sfn-teststate-parallel`
**Created**: 2026-02-12
**Status**: Draft
**Input**: User description: "Add support for Parallel state to StepFunctions TestState implementation. Relevant input validations to implement: 1) mock.result is not a valid JSON array, and definition contains a Parallel state 2) definition contains a Parallel state and mock.result is a JSON array whose size is not equal to the number of branches in the Parallel state"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Validate mock.result is a JSON array for Parallel states (Priority: P1)

A user calls the TestState API with a state machine definition containing a Parallel state and provides a `mock.result` that is not a valid JSON array. The system rejects the request with a clear validation error indicating that the mocked result must be an array.

**Why this priority**: This is the most fundamental validation — without it, the system would accept structurally invalid mock data for Parallel states, leading to confusing runtime errors or incorrect behavior. This validation also gates the ability to use Parallel states with TestState at all.

**Independent Test**: Can be tested by calling TestState with a Parallel state definition and a non-array mock.result (e.g., a string or object), verifying the error response matches AWS behavior.

**Acceptance Scenarios**:

1. **Given** a state machine definition with a Parallel state and a mock.result that is a JSON string, **When** the user calls TestState, **Then** the system returns a validation error indicating the mocked result must be an array.
2. **Given** a state machine definition with a Parallel state and a mock.result that is a JSON object, **When** the user calls TestState, **Then** the system returns a validation error indicating the mocked result must be an array.
3. **Given** a state machine definition with a Parallel state and a mock.result that is a JSON number, **When** the user calls TestState, **Then** the system returns a validation error indicating the mocked result must be an array.

---

### User Story 2 - Validate mock.result array size matches branch count (Priority: P1)

A user calls the TestState API with a Parallel state definition and provides a `mock.result` that is a valid JSON array, but whose length does not match the number of branches defined in the Parallel state. The system rejects the request with a validation error indicating the size mismatch.

**Why this priority**: This is equally critical as US1 — once the system confirms the mock is an array, it must verify structural compatibility with the Parallel state definition. Without this check, mock data would silently fail to map to branches.

**Independent Test**: Can be tested by calling TestState with a Parallel state having N branches and a mock.result array of length != N, verifying the error response matches AWS behavior.

**Acceptance Scenarios**:

1. **Given** a Parallel state with 3 branches and a mock.result array of size 2, **When** the user calls TestState, **Then** the system returns a validation error about the array size not matching the number of branches.
2. **Given** a Parallel state with 2 branches and a mock.result array of size 5, **When** the user calls TestState, **Then** the system returns a validation error about the array size not matching the number of branches.
3. **Given** a Parallel state with 2 branches and a mock.result array of size 0, **When** the user calls TestState, **Then** the system returns a validation error about the array size not matching the number of branches.

---

### User Story 3 - Successfully execute TestState with valid Parallel state mock (Priority: P2)

A user calls the TestState API with a Parallel state definition and a correctly structured mock.result (a JSON array whose length matches the number of branches). The system accepts the input and executes the test state, returning the mocked parallel execution result.

**Why this priority**: This is the happy-path scenario. While essential for complete Parallel state support, the validation stories (US1, US2) are prioritized first because they prevent invalid inputs from reaching execution.

**Independent Test**: Can be tested by calling TestState with a Parallel state having N branches and a mock.result array of exactly N elements, verifying successful execution and correct output shape.

**Acceptance Scenarios**:

1. **Given** a Parallel state with 2 branches and a mock.result array of size 2, **When** the user calls TestState, **Then** the system executes successfully and returns the mocked results as the parallel output.
2. **Given** a Parallel state with 1 branch and a mock.result array of size 1, **When** the user calls TestState, **Then** the system executes successfully.

---

### Edge Cases

- What happens when a Parallel state definition has zero branches? The system should follow AWS behavior for this edge case (likely rejected at definition validation level before mock validation).
- What happens when mock.result is null/None? The system should treat this as "no mock result provided" and follow the existing behavior for states requiring mocks.
- What happens when the Parallel state is nested inside another state (e.g., a Map containing a Parallel)? TestState operates on a single top-level state, so nesting should not affect validation of the top-level state.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST accept Parallel as a valid state type for the TestState API (adding it to the set of supported states alongside Task, Pass, Wait, Choice, Succeed, Fail, and Map).
- **FR-002**: The system MUST reject TestState requests where the definition contains a Parallel state and mock.result is not a valid JSON array, returning a validation error with a message matching AWS behavior.
- **FR-003**: The system MUST reject TestState requests where the definition contains a Parallel state and mock.result is a JSON array whose length does not equal the number of branches in the Parallel state definition, returning a validation error with a message matching AWS behavior.
- **FR-004**: The system MUST execute TestState successfully when the definition contains a Parallel state and mock.result is a valid JSON array whose length matches the number of branches.
- **FR-005**: The system MUST continue to require a mock when a Parallel state is used with TestState (Parallel states cannot be executed without mocked results, consistent with Map state behavior).
- **FR-006**: All error responses (codes and messages) MUST match the actual AWS StepFunctions TestState API responses, verified via parity/snapshot testing against real AWS.

### Key Entities

- **Parallel State Definition**: A state machine state of type "Parallel" containing a `Branches` array, where each branch is a sub-state-machine with its own `StartAt` and `States`.
- **Mock Result**: The `mock.result` field in the TestState input representing the simulated output of the state being tested. For Parallel states, this must be a JSON array with one element per branch.
- **TestState Input Validation**: The static analysis step that examines the relationship between the state definition and the mock configuration before execution begins.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All validation error responses for Parallel state TestState requests match AWS behavior exactly, as verified by snapshot tests run against real AWS.
- **SC-002**: Valid Parallel state TestState requests execute successfully and return correct mocked results, as verified by snapshot tests run against real AWS.
- **SC-003**: Existing TestState functionality for all other state types (Task, Pass, Wait, Choice, Succeed, Fail, Map) continues to work without regression.

### Assumptions

- The exact AWS error messages for Parallel state validation failures will be captured by running tests against real AWS with `TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1` before implementing.
- The Parallel state mock validation follows a pattern similar to the existing Map state mock validation (array requirement, structural match).
- The Parallel state already has a working execution implementation in LocalStack (`StateParallel` class); this feature adds TestState-specific mock support and input validation on top of it.

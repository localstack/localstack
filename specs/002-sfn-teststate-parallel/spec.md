# Feature Specification: StepFunctions TestState Parallel State Support

**Feature Branch**: `002-sfn-teststate-parallel`
**Created**: 2026-02-24
**Status**: Draft
**Input**: User description: "Add support for Parallel state to StepFunctions TestState implementation. Relevant input validations to implement: 1) mock.result is not a valid JSON array, and definition contains a Parallel state 2) definition contains a Parallel state and mock.result is a JSON array whose size is not equal to the number of branches in the Parallel state"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Validate Mock Result Format for Parallel State (Priority: P1)

A developer calls the TestState API with a state machine definition containing
a Parallel state and provides a `mockResult` for inspection. The system MUST
validate that the `mockResult` is a valid JSON array, since a Parallel state
produces an array output (one element per branch). If the `mockResult` is not a
valid JSON array, the system MUST reject the request with a clear validation
error before any execution occurs.

**Why this priority**: This is the most basic guard — without it, malformed
mock data would cause confusing downstream failures or incorrect results. It
prevents invalid input from entering the execution path.

**Independent Test**: Call TestState with a Parallel state definition and a
non-array `mockResult` (e.g., a plain JSON object or string). Verify the
response contains the expected validation error matching AWS behavior.

**Acceptance Scenarios**:

1. **Given** a Parallel state definition with 2 branches, **When** the user
   calls TestState with a `mockResult` that is a JSON object (not an array),
   **Then** the system returns a validation error indicating that mock result
   must be a JSON array for Parallel states
2. **Given** a Parallel state definition, **When** the user calls TestState
   with a `mockResult` that is a plain string (not valid JSON array),
   **Then** the system returns the same validation error
3. **Given** a non-Parallel state definition (e.g., Task state), **When** the
   user calls TestState with a non-array `mockResult`, **Then** no
   array-specific validation error occurs (existing behavior unchanged)

---

### User Story 2 - Validate Mock Result Array Size Matches Branch Count (Priority: P1)

A developer calls the TestState API with a Parallel state definition and
provides a `mockResult` that is a valid JSON array. The system MUST validate
that the array length equals the number of branches defined in the Parallel
state. A mismatch means the mock data cannot correctly simulate the parallel
execution — each branch needs exactly one corresponding mock result element.

**Why this priority**: Equally critical as US1 — even with a valid array, a
size mismatch produces incorrect simulation results. Both validations together
form the complete input guard for Parallel state mock results.

**Independent Test**: Call TestState with a Parallel state definition having N
branches and a `mockResult` array of a different size. Verify the response
contains the expected validation error matching AWS behavior.

**Acceptance Scenarios**:

1. **Given** a Parallel state definition with 3 branches, **When** the user
   calls TestState with a `mockResult` array of size 2, **Then** the system
   returns a validation error indicating the array size does not match the
   number of branches
2. **Given** a Parallel state definition with 2 branches, **When** the user
   calls TestState with a `mockResult` array of size 5, **Then** the system
   returns the same type of validation error
3. **Given** a Parallel state definition with 2 branches, **When** the user
   calls TestState with a `mockResult` array of size 2, **Then** validation
   passes and the TestState execution proceeds

---

### User Story 3 - Execute Parallel State via TestState (Priority: P2)

A developer calls the TestState API with a valid Parallel state definition and
correctly-sized mock results. The system MUST execute the Parallel state,
applying each mock result element to its corresponding branch, and return the
combined output matching AWS TestState behavior.

**Why this priority**: This is the happy-path execution that delivers the core
value — once input validation (US1 and US2) is in place, users need the actual
Parallel state execution to work correctly.

**Independent Test**: Call TestState with a Parallel state definition and a
valid `mockResult` array matching branch count. Verify the response output
matches the expected AWS behavior captured in snapshots.

**Acceptance Scenarios**:

1. **Given** a Parallel state definition with 2 branches and a valid
   `mockResult` array of size 2, **When** the user calls TestState,
   **Then** the system executes the Parallel state and returns output matching
   AWS behavior
2. **Given** a Parallel state with branches that include result selectors or
   output paths, **When** the user calls TestState with valid mock results,
   **Then** the output reflects the correct application of those processing
   rules per branch

---

### Edge Cases

- What happens when the Parallel state has zero branches (empty Branches
  array)? The system should match AWS behavior for this edge case.
- What happens when `mockResult` is an empty JSON array `[]` but the Parallel
  state has branches? Should fail validation (size mismatch).
- What happens when `mockResult` is `null` or not provided at all for a
  Parallel state? The system should match AWS behavior.
- What happens when the Parallel state has nested Parallel states within
  branches? Only the top-level Parallel state's branch count is validated
  against the mock result array size.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST reject TestState requests where the definition
  contains a Parallel state and the `mockResult` is not a valid JSON array,
  returning the same error response as AWS
- **FR-002**: System MUST reject TestState requests where the definition
  contains a Parallel state and the `mockResult` is a valid JSON array whose
  length does not equal the number of branches in the Parallel state, returning
  the same error response as AWS
- **FR-003**: System MUST accept and execute TestState requests where the
  definition contains a Parallel state and the `mockResult` is a valid JSON
  array whose length equals the number of branches
- **FR-004**: System MUST produce output for Parallel state TestState
  executions that matches AWS behavior (validated via snapshot testing)
- **FR-005**: System MUST NOT alter existing TestState behavior for non-Parallel
  state types (Task, Pass, Choice, Wait, Map, etc.)
- **FR-006**: Validation errors MUST match the exact error format and message
  returned by AWS for the same invalid inputs

### Key Entities

- **Parallel State Definition**: A Step Functions state of type "Parallel"
  containing a `Branches` array, where each branch is a sub-state-machine with
  its own `States` and `StartAt`
- **Mock Result**: The `mockResult` field in the TestState inspection data,
  which for Parallel states MUST be a JSON array with one element per branch
- **TestState Response**: The API response containing execution output, status,
  and any error information

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of TestState validation error responses for Parallel state
  mock result issues match the AWS-recorded snapshots
- **SC-002**: 100% of TestState successful Parallel state execution responses
  match the AWS-recorded snapshots
- **SC-003**: All existing TestState tests for non-Parallel states continue to
  pass without modification (zero regressions)

### Assumptions

- The TestState API already exists in LocalStack with support for other state
  types (Task, Pass, Choice, etc.)
- AWS parity is verified by running tests against real AWS with
  `SNAPSHOT_UPDATE=1` and comparing snapshots
- The AWS error format for these validation failures is deterministic and can
  be captured in snapshot tests

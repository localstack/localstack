# Feature Specification: StepFunctions TestState Parallel State Support

**Feature Branch**: `002-sfn-teststate-parallel`
**Created**: 2026-02-24
**Status**: Draft
**Input**: User description: "Add support for Parallel state to StepFunctions TestState implementation. Relevant input validations to implement: 1) mock.result is not a valid JSON array, and definition contains a Parallel state 2) definition contains a Parallel state and mock.result is a JSON array whose size is not equal to the number of branches in the Parallel state"

## Clarifications

### Session 2026-02-24

- Q: Should null/omitted mockResult for a Parallel state be in scope? → A: Yes, add FR for null/omitted mockResult → validation error
- Q: Should empty Branches array be in scope? → A: Yes, add FR to capture AWS validation error for empty Branches
- Q: Should nested Parallel states within branches be tested? → A: No, TestState only validates the top-level state; document as assumption
- Q: Should Parallel state work at all inspection levels? → A: Yes, test at all inspection levels to ensure full parity
- Q: Should InputPath/ResultPath/OutputPath on the Parallel state itself be tested? → A: Yes, test I/O processing fields on the Parallel state

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
4. **Given** a Parallel state definition, **When** the user calls TestState
   with `mockResult` set to `null` or omitted entirely, **Then** the system
   returns a validation error matching AWS behavior

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
4. **Given** a Parallel state definition with 0 branches (empty Branches
   array), **When** the user calls TestState, **Then** the system returns
   a validation error matching AWS behavior for invalid state definitions

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
2. **Given** a Parallel state with `InputPath`, `ResultPath`, or `OutputPath`
   defined on the Parallel state itself, **When** the user calls TestState
   with valid mock results, **Then** the output reflects the correct
   application of those I/O processing rules
3. **Given** a Parallel state with branches that include result selectors or
   output paths, **When** the user calls TestState with valid mock results,
   **Then** the output reflects the correct application of those processing
   rules per branch
4. **Given** a valid Parallel state TestState request with `inspectionLevel`
   set to any supported level (INFO, DEBUG, TRACE), **When** the user calls
   TestState, **Then** the response format and content match AWS behavior for
   that inspection level

---

### Edge Cases

- **Empty Branches array**: A Parallel state with zero branches (empty
  `Branches` array) MUST be rejected with the same error as AWS. This is
  tested as part of US2 (FR-008).
- **Empty mockResult array with branches**: An empty JSON array `[]` as
  `mockResult` when the Parallel state has branches MUST fail validation
  (size mismatch — covered by FR-002).
- **Null/omitted mockResult**: When `mockResult` is `null` or not provided for
  a Parallel state, the system MUST return a validation error matching AWS
  behavior (FR-007).
- **Nested Parallel states within branches**: NOT tested. TestState evaluates
  a single state definition — the top-level state being tested. Nested states
  within branches are internal to the branch's sub-state-machine and are not
  directly executed or validated by TestState's mock result mechanism. Only the
  top-level Parallel state's branch count is relevant for mock result
  validation.
- **Inspection levels**: Parallel state TestState execution MUST produce
  correct output at all supported inspection levels (INFO, DEBUG, TRACE),
  matching AWS behavior for each level (FR-009).

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
- **FR-007**: System MUST reject TestState requests where the definition
  contains a Parallel state and the `mockResult` is `null` or omitted,
  returning the same error response as AWS
- **FR-008**: System MUST reject TestState requests where the definition
  contains a Parallel state with an empty `Branches` array, returning the
  same error response as AWS
- **FR-009**: Parallel state TestState execution MUST produce correct responses
  at all supported inspection levels (INFO, DEBUG, TRACE), matching AWS
  behavior for each level
- **FR-010**: System MUST correctly apply `InputPath`, `ResultPath`, and
  `OutputPath` fields defined on the Parallel state itself during TestState
  execution, matching AWS behavior

### Key Entities

- **Parallel State Definition**: A Step Functions state of type "Parallel"
  containing a `Branches` array, where each branch is a sub-state-machine with
  its own `States` and `StartAt`
- **Mock Result**: The `mockResult` field in the TestState inspection data,
  which for Parallel states MUST be a JSON array with one element per branch
- **TestState Response**: The API response containing execution output, status,
  and any error information
- **Inspection Level**: The `inspectionLevel` parameter controlling response
  detail (INFO, DEBUG, TRACE), affecting what metadata is included in the
  TestState response

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of TestState validation error responses for Parallel state
  mock result issues match the AWS-recorded snapshots
- **SC-002**: 100% of TestState successful Parallel state execution responses
  match the AWS-recorded snapshots
- **SC-003**: All existing TestState tests for non-Parallel states continue to
  pass without modification (zero regressions)
- **SC-004**: Parallel state TestState responses match AWS snapshots at all
  supported inspection levels

### Assumptions

- The TestState API already exists in LocalStack with support for other state
  types (Task, Pass, Choice, etc.)
- AWS parity is verified by running tests against real AWS with
  `SNAPSHOT_UPDATE=1` and comparing snapshots
- The AWS error format for these validation failures is deterministic and can
  be captured in snapshot tests
- Nested Parallel states within branches are out of scope — TestState
  evaluates only the top-level state definition

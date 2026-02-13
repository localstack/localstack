---
description: "Task list for StepFunctions TestState Parallel State Support"
---

# Tasks: StepFunctions TestState Parallel State Support

**Input**: Design documents from `/specs/001-sfn-teststate-parallel/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md

**Tests**: Included — parity testing is required per FR-006 and AGENTS.md development process.

**⚠️ SNAPSHOT RULE**: Any task that involves recording an AWS snapshot (tests using `sfn_snapshot.match`) MUST NOT be marked as completed unless the snapshot was actually recorded by running the test against real AWS with:
```
AWS_PROFILE=ls-sandbox TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1 python -m pytest <test_path> -v
```
If the snapshot file was not created/updated, the task remains incomplete.

**Organization**: Tasks are grouped by user story. US1 and US2 are both P1 and share
the same validation method, so they are combined into a single phase.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Source**: `localstack-core/localstack/services/stepfunctions/`
- **Tests**: `tests/aws/services/stepfunctions/`
- **Templates**: `tests/aws/services/stepfunctions/templates/test_state/`

---

## Phase 1: Setup

**Purpose**: Create test fixtures and templates needed by all stories

- [X] T001 [P] Create Parallel state test template with 2 branches in tests/aws/services/stepfunctions/templates/test_state/statemachines/base_parallel_state.json5 (follow base_map_state.json5 pattern: Parallel type with 2 branches, each containing a simple Pass state with End: true)
- [X] T002 [P] Add BASE_PARALLEL_STATE constant to tests/aws/services/stepfunctions/templates/test_state/test_state_templates.py (follow BASE_MAP_STATE pattern, pointing to statemachines/base_parallel_state.json5)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Enable Parallel as a supported TestState type — MUST complete before any user story

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T003 Add StateType.Parallel to _SUPPORTED_STATE_TYPES set in localstack-core/localstack/services/stepfunctions/asl/static_analyser/test_state/test_state_analyser.py (line 60-68, add StateType.Parallel to the set alongside the existing 7 types)

**Checkpoint**: Parallel states are now accepted by the TestState static analyser. The existing `validate_test_state_allows_mocking()` already handles Parallel (line 139 checks `isinstance(test_state, (StateMap, StateParallel))`), so "Parallel requires mock" validation works automatically.

---

## Phase 3: User Stories 1 & 2 — Mock Result Validation (Priority: P1) 🎯 MVP

**Goal**: Reject invalid mock.result for Parallel states: must be a JSON array (US1) and array size must match branch count (US2).

**Independent Test**: Call TestState with a Parallel definition and (a) non-array mock.result → validation error, (b) wrong-size array → validation error.

### Tests for US1 & US2

> **NOTE: Write these tests FIRST, run against AWS to capture snapshots, ensure they FAIL against LocalStack, then implement**

- [X] T004 [P] [US1] Add test_mock_result_is_not_array_on_parallel_state to tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py (follow test_mock_result_is_not_array_on_map_state_without_result_writer pattern: load BASE_PARALLEL_STATE template, provide non-array mock.result e.g. JSON object, pytest.raises + sfn_snapshot.match)
- [X] T005 [P] [US2] Add test_mock_result_array_size_mismatch_on_parallel_state to tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py (use BASE_PARALLEL_STATE template with 2 branches, provide mock.result as JSON array of size 1, pytest.raises + sfn_snapshot.match)
- [X] T006 [P] [US1] Add Parallel state entries to STATES_REQUIRING_MOCKS list in tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py (add pytest.param(TST.BASE_PARALLEL_STATE, id="ParallelState") so existing test_state_type_requires_mock covers Parallel without mock)
- [ ] T015 [P] [US1] 🎯 SNAPSHOT Record AWS snapshots for validation tests by running: AWS_PROFILE=ls-sandbox TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1 python -m pytest tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py::TestStateMockValidation::test_mock_result_is_not_array_on_parallel_state tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py::TestStateMockValidation::test_mock_result_array_size_mismatch_on_parallel_state tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py::TestStateMockValidation::test_state_type_requires_mock[ParallelState] -v (verify snapshot files are created/updated)

### Implementation for US1 & US2

- [X] T007 [US1] Add validate_mock_result_matches_parallel_definition() static method to TestStateStaticAnalyser in localstack-core/localstack/services/stepfunctions/asl/static_analyser/test_state/test_state_analyser.py (accept mock_result: Any and test_state: StateParallel; check 1: if not isinstance(mock_result, list) raise ValidationException("Mocked result must be an array."); check 2: if len(mock_result) != len(test_state.branches.programs) raise ValidationException with branch count mismatch message from AWS snapshot)
- [X] T008 [US2] Add isinstance(test_state, StateParallel) dispatch in validate_mock() method in localstack-core/localstack/services/stepfunctions/asl/static_analyser/test_state/test_state_analyser.py (after the existing StateMap check at line 120-123, add: if isinstance(test_state, StateParallel): call validate_mock_result_matches_parallel_definition)

**Checkpoint**: US1 and US2 validation tests pass against LocalStack with snapshot parity to AWS.

---

## Phase 4: User Story 3 — Successful Parallel TestState Execution (Priority: P2)

**Goal**: Execute TestState with a valid Parallel state mock and return correct mocked results.

**Independent Test**: Call TestState with a Parallel state having 2 branches and a mock.result array of size 2 — verify successful execution and correct output.

### Tests for US3

> **NOTE: Write test FIRST, run against AWS to capture snapshot, ensure it FAILS against LocalStack, then implement**

- [X] T009 [US3] Add test_parallel_state_mock_execution to tests/aws/services/stepfunctions/v2/test_state/test_test_state_mock_scenarios.py (or test_state_mock_validation.py — use BASE_PARALLEL_STATE with 2 branches, provide valid mock.result array of 2 elements, verify successful execution output with sfn_snapshot.match)
- [ ] T016 [US3] 🎯 SNAPSHOT Record AWS snapshot for execution test by running: AWS_PROFILE=ls-sandbox TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1 python -m pytest tests/aws/services/stepfunctions/v2/test_state/test_test_state_mock_scenarios.py::TestStateMockScenarios::test_parallel_state_mock_execution -v (verify snapshot file is created/updated)

### Implementation for US3

- [X] T010 [US3] Create MockedStateParallel class in localstack-core/localstack/services/stepfunctions/asl/component/test_state/state/parallel.py (extend MockedBaseState[StateParallel] following MockedStateMap pattern; implement _apply_patches() to: wrap with MockedStateExecution, patch branches._eval_body with wrap_with_mock to inject mocked results per branch instead of running actual branch workers)
- [X] T011 [US3] Update _decorate_state_field() in localstack-core/localstack/services/stepfunctions/asl/parse/test_state/preprocessor.py (add elif isinstance(state_field, StateParallel): MockedStateParallel.wrap(state_field, is_single_state) after the StateMap check at line 99-100; add import for MockedStateParallel and StateParallel)
- [X] T012 [US3] Update find_state() in localstack-core/localstack/services/stepfunctions/asl/parse/test_state/preprocessor.py (add recursion into Parallel branches: for each program in state.branches.programs, search program.states.states — follow the existing StateMap recursion pattern at lines 112-115)

**Checkpoint**: Valid Parallel state TestState requests execute successfully with mocked results matching AWS snapshot.

---

## Phase 5: Polish & Cross-Cutting Concerns

**Purpose**: Regression testing and code quality

- [ ] T013 Run full TestState mock validation test suite against LocalStack: pytest tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py -v (verify no regressions to Map, Task, Pass, Fail, Succeed, Choice, Wait states; requires T015 snapshots to be recorded first)
- [X] T014 Run make format and make lint on all modified files
- [ ] T017 Run test_parallel_state_mock_execution against LocalStack to verify parity with AWS snapshot (requires T016 snapshot to be recorded first)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup — BLOCKS all user stories
- **US1 & US2 (Phase 3)**: Depends on Foundational (Phase 2) — validation only, no execution wrapper needed
- **US3 (Phase 4)**: Depends on Phase 3 (validation must work before execution path)
- **Polish (Phase 5)**: Depends on all user stories being complete and all snapshots being recorded (T015, T016)

### User Story Dependencies

- **US1 + US2 (P1)**: Can start after Phase 2. Implemented in the same validation method. No dependency on US3.
- **US3 (P2)**: Can start after Phase 3. Requires the MockedStateParallel wrapper and preprocessor integration, which are separate from validation.

### Within Each Phase

- Tests MUST be written and FAIL before implementation
- T004, T005, T006 can run in parallel (different test methods, same file but independent)
- T007, T008 are sequential (T007 creates the method, T008 calls it)
- T010, T011, T012 are sequential (T010 creates the class, T011 imports it, T012 extends find_state)

### Parallel Opportunities

- T001 and T002 can run in parallel (different files)
- T004, T005, T006 can run in parallel (independent test methods)

---

## Implementation Strategy

### MVP First (US1 + US2 Only)

1. Complete Phase 1: Setup (T001, T002)
2. Complete Phase 2: Foundational (T003)
3. Complete Phase 3: US1 + US2 validation tests and implementation (T004-T008)
4. **STOP and VALIDATE**: Run validation tests against LocalStack
5. This delivers the two requested input validations

### Full Delivery

1. Complete MVP (Phases 1-3)
2. Record AWS snapshots for validation tests (T015)
3. Complete Phase 4: US3 execution support (T009-T012)
4. Record AWS snapshot for execution test (T016)
5. Complete Phase 5: Polish (T013, T014, T017)
6. All Parallel state TestState scenarios are complete with recorded AWS snapshots

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- T007 implements both US1 (array check) and US2 (size check) in a single method since they are sequential checks within the same validation function
- Exact AWS error messages for branch-count mismatch (T007) will be captured from snapshot tests run against real AWS before implementing
- The existing `validate_test_state_allows_mocking()` already handles Parallel + StateMap in the "requires mock" check, so no implementation change needed for FR-005

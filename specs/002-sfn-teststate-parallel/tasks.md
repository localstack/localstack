# Tasks: StepFunctions TestState Parallel State Support

**Input**: Design documents from `/specs/002-sfn-teststate-parallel/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md

**Tests**: Required by constitution (Test-First Development, NON-NEGOTIABLE).

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Create test templates and register Parallel as a supported state type

- [ ] T001 [P] Create base Parallel state JSON5 template with 2 branches (each containing a Pass state with End:true) in `tests/aws/services/stepfunctions/templates/test_state/statemachines/base_parallel_state.json5`
- [ ] T002 [P] Create Parallel state with I/O processing fields (InputPath, ResultPath, OutputPath) JSON5 template in `tests/aws/services/stepfunctions/templates/test_state/statemachines/io_parallel_state.json5`
- [ ] T003 Register new Parallel template paths in `tests/aws/services/stepfunctions/templates/test_state/test_state_templates.py` (add `BASE_PARALLEL_STATE` and `IO_PARALLEL_STATE` constants)

**Checkpoint**: Templates ready. Test authoring can begin.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Add `StateType.Parallel` to the supported state types so TestState accepts Parallel definitions

**CRITICAL**: No user story work can begin until this phase is complete

- [ ] T004 Add `StateType.Parallel` to `_SUPPORTED_STATE_TYPES` set in `localstack-core/localstack/services/stepfunctions/asl/static_analyser/test_state/test_state_analyser.py`

**Checkpoint**: Foundation ready — TestState will no longer reject Parallel state definitions outright. User story work can now begin.

---

## Phase 3: User Story 1 — Validate Mock Result Format for Parallel State (Priority: P1)

**Goal**: Reject TestState requests where mock result is not a valid JSON array for Parallel states (FR-001, FR-007)

**Independent Test**: Call TestState with a Parallel state definition and a non-array mockResult. Verify the validation error matches AWS.

### Tests for User Story 1

> **NOTE: Write these tests FIRST, run against AWS to record snapshots, ensure they FAIL against LocalStack before implementation**

- [ ] T005 [US1] Write test `test_mock_result_is_not_array_on_parallel_state` in `tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py` — call TestState with base_parallel_state template and a JSON object as mock result; expect ValidationException; use `sfn_snapshot.match()`
- [ ] T006 [US1] Write test `test_parallel_state_requires_mock` in `tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py` — call TestState with base_parallel_state template and no mock; expect InvalidDefinition error; add to `STATES_REQUIRING_MOCKS` parametrize list
- [ ] T007 [US1] Run US1 tests against AWS with `AWS_PROFILE=ls-sandbox TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1 pytest tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py -v -k "parallel"` to record snapshots. Task is NOT complete until snapshot files are created/updated on disk.

### Implementation for User Story 1

- [ ] T008 [US1] Add `validate_mock_result_matches_parallel_definition` static method to `TestStateStaticAnalyser` in `localstack-core/localstack/services/stepfunctions/asl/static_analyser/test_state/test_state_analyser.py` — check `isinstance(mock_result, list)`, raise `ValidationException` if not
- [ ] T009 [US1] Wire Parallel validation into `TestStateStaticAnalyser.validate_mock` in `localstack-core/localstack/services/stepfunctions/asl/static_analyser/test_state/test_state_analyser.py` — add `isinstance(test_state, StateParallel)` branch after the `isinstance(test_state, StateMap)` check, calling the new validation method
- [ ] T010 [US1] Start LocalStack with `python -m localstack.dev.run` and run US1 tests against LocalStack with `pytest tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py -v -k "parallel"`. Task is NOT complete until all tests pass.

**Checkpoint**: Parallel state mock-result-must-be-array validation works. Snapshots match AWS.

---

## Phase 4: User Story 2 — Validate Mock Result Array Size Matches Branch Count (Priority: P1)

**Goal**: Reject TestState requests where mock result array size does not match the number of branches (FR-002, FR-008)

**Independent Test**: Call TestState with a Parallel state definition with N branches and a mock result array of different size. Verify the validation error matches AWS.

### Tests for User Story 2

> **NOTE: Write these tests FIRST, run against AWS to record snapshots, ensure they FAIL against LocalStack before implementation**

- [ ] T011 [US2] Write test `test_mock_result_array_size_mismatch_on_parallel_state` in `tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py` — call TestState with base_parallel_state template (2 branches) and a mock result array of size 1; expect ValidationException; use `sfn_snapshot.match()`
- [ ] T012 [US2] Run US2 tests against AWS with `AWS_PROFILE=ls-sandbox TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1 pytest tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py -v -k "mismatch"` to record snapshots. Task is NOT complete until snapshot files are created/updated on disk.

### Implementation for User Story 2

- [ ] T013 [US2] Extend `validate_mock_result_matches_parallel_definition` in `localstack-core/localstack/services/stepfunctions/asl/static_analyser/test_state/test_state_analyser.py` to also check `len(mock_result) == len(test_state.branches.programs)`, raising `ValidationException` if size mismatches
- [ ] T014 [US2] Start LocalStack with `python -m localstack.dev.run` and run US2 tests against LocalStack with `pytest tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py -v -k "mismatch"`. Task is NOT complete until all tests pass.

**Checkpoint**: Both validation guards (format + size) work. All US1 + US2 tests pass against both AWS and LocalStack.

---

## Phase 5: User Story 3 — Execute Parallel State via TestState (Priority: P2)

**Goal**: Execute Parallel state with valid mock results and return output matching AWS behavior at all inspection levels (FR-003, FR-004, FR-009, FR-010)

**Independent Test**: Call TestState with a valid Parallel state definition and correctly-sized mock results. Verify output matches AWS snapshots at all inspection levels.

### Tests for User Story 3

> **NOTE: Write these tests FIRST, run against AWS to record snapshots, ensure they FAIL against LocalStack before implementation**

- [ ] T015 [P] [US3] Write test `test_base_parallel_state_mock_success` in `tests/aws/services/stepfunctions/v2/test_state/test_test_state_mock_scenarios.py` — call TestState with base_parallel_state template (2 branches) and valid mock result array of size 2; parametrize over all inspection levels (INFO, DEBUG, TRACE); use `sfn_snapshot.match()`
- [ ] T016 [P] [US3] Write test `test_io_parallel_state_mock_success` in `tests/aws/services/stepfunctions/v2/test_state/test_test_state_mock_scenarios.py` — call TestState with io_parallel_state template (Parallel with InputPath/ResultPath/OutputPath) and valid mock result array; parametrize over all inspection levels; use `sfn_snapshot.match()`
- [ ] T017 [US3] Run US3 tests against AWS with `AWS_PROFILE=ls-sandbox TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1 pytest tests/aws/services/stepfunctions/v2/test_state/test_test_state_mock_scenarios.py -v -k "parallel"` to record snapshots. Task is NOT complete until snapshot files are created/updated on disk.

### Implementation for User Story 3

- [ ] T018 [US3] Create `MockedStateParallel` class in `localstack-core/localstack/services/stepfunctions/asl/component/test_state/state/parallel.py` — extend `MockedBaseState[StateParallel]`, follow `MockedStateMap` pattern; patch `BranchesDecl._eval_body` to distribute mock result array elements to branches
- [ ] T019 [US3] Register `StateParallel` in `_decorate_state_field` function in `localstack-core/localstack/services/stepfunctions/asl/parse/test_state/preprocessor.py` — add `isinstance(state_field, StateParallel)` branch that calls `MockedStateParallel.wrap(state_field, is_single_state)`; add necessary imports
- [ ] T020 [US3] Start LocalStack with `python -m localstack.dev.run` and run US3 tests against LocalStack with `pytest tests/aws/services/stepfunctions/v2/test_state/test_test_state_mock_scenarios.py -v -k "parallel"`. Task is NOT complete until all tests pass.

**Checkpoint**: Parallel state TestState execution works end-to-end. All US3 tests pass against both AWS and LocalStack at all inspection levels.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Regression verification and cleanup

- [ ] T021 Run all existing TestState tests against LocalStack to verify zero regressions: `pytest tests/aws/services/stepfunctions/v2/test_state/ -v`. Task is NOT complete unless all pre-existing tests still pass.
- [ ] T022 Run quickstart.md validation — manually verify the 3 CLI scenarios from `specs/002-sfn-teststate-parallel/quickstart.md` against running LocalStack

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on T003 (templates registered) — BLOCKS all user stories
- **US1 (Phase 3)**: Depends on Phase 2 completion
- **US2 (Phase 4)**: Depends on Phase 3 completion (US2 validation extends US1's validation method)
- **US3 (Phase 5)**: Depends on Phase 2 completion (independent of US1/US2 for test writing, but implementation depends on validation being in place)
- **Polish (Phase 6)**: Depends on all user stories being complete

### Within Each User Story

1. Tests MUST be written FIRST (T005-T007, T011-T012, T015-T017)
2. Tests MUST be run against AWS to record snapshots — task NOT complete without snapshots on disk
3. Implementation follows (T008-T009, T013, T018-T019)
4. Tests MUST pass against LocalStack — task NOT complete without green tests (T010, T014, T020)

### Parallel Opportunities

- T001 and T002 (template creation) can run in parallel
- T015 and T016 (US3 test writing) can run in parallel
- US1 and US2 test writing (T005-T007, T011-T012) could run in parallel, but implementation is sequential (T013 extends T008)

---

## Implementation Strategy

### MVP First (User Stories 1 + 2)

1. Complete Phase 1: Setup (templates)
2. Complete Phase 2: Foundational (StateType registration)
3. Complete Phase 3: US1 (mock format validation)
4. Complete Phase 4: US2 (mock size validation)
5. **STOP and VALIDATE**: Both validation error paths match AWS snapshots

### Full Delivery

6. Complete Phase 5: US3 (Parallel state execution)
7. Complete Phase 6: Regression verification
8. All 10 functional requirements satisfied

---

## Notes

- All tests use `@markers.aws.validated` decorator and `sfn_snapshot.match()` for assertions
- Use `aws_client_no_sync_prefix` fixture for TestState calls (disables sync prefix on localhost)
- Snapshot files (`*.snapshot.json`, `*.validation.json`) are auto-generated — never edit manually
- Start LocalStack with `python -m localstack.dev.run` (from `.venv`) for local verification — NOT `localstack start`
- Constitution Principle III: If a task involves recording a snapshot, the task MUST NOT be marked complete unless the snapshot was actually recorded on disk
- Constitution Principle IV: Implementation tasks MUST NOT be marked complete unless tests pass against LocalStack

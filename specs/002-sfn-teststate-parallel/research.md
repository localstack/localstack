# Research: StepFunctions TestState Parallel State Support

**Date**: 2026-02-24 | **Branch**: `002-sfn-teststate-parallel`
**Constitution**: v1.1.0 (includes 5-step LocalStack Lifecycle Management)

## R1: Current TestState Architecture

**Decision**: Extend the existing TestState mock/decorator pattern to support
Parallel states, following the same architecture as Map state support.

**Rationale**: The TestState system follows a clear pattern:
1. `TestStateStaticAnalyser` validates inputs before execution
2. `TestStatePreprocessor` decorates states with mock/inspection behavior
3. Mocked state classes (`MockedStateTask`, `MockedStateMap`, `MockedCommonState`)
   wrap real states to intercept execution and inject mock data

Map state already has full support via `MockedStateMap` and
`validate_mock_result_matches_map_definition`. Parallel state needs the same
treatment.

**Alternatives considered**:
- Creating a completely new execution path for Parallel → rejected because the
  existing decorator pattern is well-tested and consistent
- Reusing Map state logic → rejected because Parallel has different semantics
  (branches vs iterations)

## R2: Where Validation Must Be Added

**Decision**: Add Parallel state mock result validation in
`TestStateStaticAnalyser.validate_mock` (same location as Map state validation).

**Rationale**: The `validate_mock` method already:
- Parses the definition to get the test state type
- Checks if mock is allowed for the state type
- Validates mock result format for Map states
- Validates mock result shape for service tasks

Adding Parallel validation here follows the established pattern.

**Key findings**:
- `validate_test_state_allows_mocking` already handles `StateParallel` — it
  requires a mock when testing a Parallel state (same as Map)
- `_SUPPORTED_STATE_TYPES` does NOT include `StateType.Parallel` — this must
  be added
- The validation must check:
  1. `mock_result` is a list (JSON array)
  2. `len(mock_result) == len(test_state.branches.programs)`

## R3: Where Execution Support Must Be Added

**Decision**: Create `MockedStateParallel` class following `MockedStateMap`
pattern, and register it in `_decorate_state_field` in the preprocessor.

**Rationale**: Each execution state type has a corresponding mocked class:
- `StateTask` → `MockedStateTask`
- `StateMap` → `MockedStateMap`
- `StateParallel` → needs `MockedStateParallel`

The preprocessor's `_decorate_state_field` function must be extended to handle
`StateParallel`.

## R4: Parallel State Branch Execution with Mocks

**Decision**: Mock each branch's iteration component individually by assigning
each mock result array element to the corresponding branch program.

**Rationale**: `BranchesDecl._eval_body` creates an `env_frame` per branch
program and collects results. For mocked execution, each branch should receive
its corresponding mock result element instead of actually executing.

The `TestStateMock._result_stack` currently stores a single result. For Parallel
states, the mock result is an array where element `i` corresponds to branch `i`.
The mock needs to distribute results across branches.

## R5: Inspection Level Behavior

**Decision**: Inspection data for Parallel states follows the same pattern as
other states — populated at DEBUG and TRACE levels via `to_test_state_output`.

**Rationale**: `TestStateExecution.to_test_state_output` already handles
inspection levels generically:
```python
match inspection_level:
    case InspectionLevel.TRACE:
        test_state_output["inspectionData"] = self.exec_worker.env.inspection_data
    case InspectionLevel.DEBUG:
        test_state_output["inspectionData"] = self.exec_worker.env.inspection_data
```

No special handling is needed for Parallel states at the output level. The
inspection data is populated during execution by the decorated components.

## R6: Test Template Structure

**Decision**: Create JSON5 state templates for Parallel states following the
existing template pattern in `tests/aws/services/stepfunctions/templates/test_state/statemachines/`.

**Rationale**: All existing test state templates are JSON5 files defining a
single state. Parallel state templates need:
- A base Parallel state with 2 branches (each containing a Pass state)
- Variants with InputPath, ResultPath, OutputPath on the Parallel state

## R7: State Type Registration

**Decision**: Add `StateType.Parallel` to `_SUPPORTED_STATE_TYPES` in
`TestStateStaticAnalyser`.

**Rationale**: The static analyser's `visitState_type` method checks against
`_SUPPORTED_STATE_TYPES` and raises an error for unsupported types. Without
adding Parallel, the definition validation would reject Parallel states
before mock validation even runs.

# Data Model: StepFunctions TestState Parallel State Support

## Entities

### StateParallel (existing)

Already implemented in the codebase. Key attributes relevant to this feature:

- `branches: BranchesDecl` — Contains a `programs: list[Program]` where each `Program`
  represents one branch of the Parallel state. The length of this list determines the
  expected mock result array size.
- `parargs: Parargs | None` — Optional parameters/arguments for the Parallel state.
- Inherits from `ExecutionState` which provides `catch`, `retry`, `input_path`,
  `result_path`, `result_selector`.

### BranchesDecl (existing)

- `programs: list[Program]` — List of branch programs. Each program has its own
  `StartAt` and `States`.
- `_eval_body()` — Executes all branches in parallel using `BranchWorkerPool`,
  collects results into a list.

### MockedStateParallel (new)

Follows `MockedBaseState[StateParallel]` pattern from `MockedStateMap`.

- Wraps a `StateParallel` instance for TestState execution.
- `_apply_patches()` — Patches `branches._eval_body` to inject mocked results
  instead of running actual branch execution.
- `add_inspection_data()` — Populates inspection data after execution.

### TestState Mock Result (for Parallel)

- Must be a JSON array.
- Array length must equal `len(state_parallel.branches.programs)`.
- Each element is the mocked output of the corresponding branch.

## Validation Rules

| Field | Rule | Error |
|-------|------|-------|
| mock.result (Parallel, no mock) | Mock is required for Parallel states | `InvalidDefinition`: "TestState API does not support Map or Parallel states..." |
| mock.result (Parallel, not array) | Must be a JSON array | `ValidationException`: "Mocked result must be an array." |
| mock.result (Parallel, wrong size) | Array length must equal branch count | `ValidationException`: TBD from AWS parity test |

## State Transitions

No new state transitions. The existing Parallel state execution flow is preserved;
only the TestState mock injection path is new.

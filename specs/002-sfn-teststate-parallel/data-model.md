# Data Model: StepFunctions TestState Parallel State Support

## Entities

### StateParallel (existing)

Located at: `localstack-core/localstack/services/stepfunctions/asl/component/state/state_execution/state_parallel/state_parallel.py`

- `branches: BranchesDecl` — contains `programs: list[Program]`, one per branch
- `parargs: Parargs | None` — optional Parameters/Arguments
- Inherits from `ExecutionState` which provides:
  - `input_path: InputPath | None`
  - `result_path: ResultPath | None`
  - `result_selector: ResultSelector | None`
  - `output_path: OutputPath | None` (via `CommonStateField`)
  - `catch: CatchDecl | None`
  - `retry: RetryDecl | None`

### BranchesDecl (existing)

Located at: `localstack-core/localstack/services/stepfunctions/asl/component/state/state_execution/state_parallel/branches_decl.py`

- `programs: list[Program]` — one Program per branch
- `len(programs)` = number of branches in the Parallel state

### MockedStateParallel (new)

To be created at: `localstack-core/localstack/services/stepfunctions/asl/component/test_state/state/parallel.py`

- Extends `MockedBaseState[StateParallel]`
- Follows the same pattern as `MockedStateMap`
- Patches `BranchesDecl._eval_body` to use mock results instead of real
  branch execution
- Each element of the mock result array maps to the corresponding branch

### TestStateMock (existing, needs modification)

Located at: `localstack-core/localstack/services/stepfunctions/backend/test_state/test_state_mock.py`

- `_result_stack: list[TestStateMockedResponse]` — currently stores a single
  result
- For Parallel states, the mock result is a JSON array; each element is a
  separate result for a branch
- The mock result parsing in `__init__` stores the parsed JSON as a single
  `TestStateResponseReturn` — for Parallel states, each array element needs
  to be accessible individually by the branch execution

## Validation Rules

| Rule | Input | Condition | Error |
|------|-------|-----------|-------|
| Mock required | Parallel state + no mock | `mock_input is None and isinstance(test_state, StateParallel)` | `InvalidDefinition` (already handled) |
| Array format | Parallel state + mock result | `not isinstance(mock_result, list)` | `ValidationException` |
| Array size | Parallel state + mock result array | `len(mock_result) != len(test_state.branches.programs)` | `ValidationException` |

## State Transitions

```
TestState request received
  → Static analysis (validate definition, state type)
  → Mock validation
    → Is Parallel state?
      → No mock? → InvalidDefinition error (existing)
      → Mock result not JSON array? → ValidationException
      → Array size != branch count? → ValidationException
      → Valid → proceed to execution
  → Execution
    → MockedStateParallel wraps StateParallel
    → Each branch receives its corresponding mock result element
    → Results collected into array output
  → Output formatting (inspection level applied)
```

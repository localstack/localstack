## Why

The StepFunctions TestState API currently supports mocking for Map states but not Parallel states. AWS supports testing Parallel states with mock configurations, and LocalStack needs to implement this for parity. Specifically, two input validations are missing: (1) when a Parallel state definition is provided with a mock result that is not a valid JSON array, and (2) when the mock result is a JSON array whose size does not match the number of branches in the Parallel state definition.

## What Changes

- Add `StateParallel` to the `_SUPPORTED_STATE_TYPES` set in `TestStateStaticAnalyser` (note: `StateParallel` is already allowed when a mock is provided — the analyser just needs to include it in the visitor's supported types)
- Add a new static validation method `validate_mock_result_matches_parallel_definition` in `TestStateStaticAnalyser` that enforces:
  - Mock result must be a JSON array (raises `ValidationException` if not)
  - Mock result array length must equal the number of branches in the Parallel state definition (raises `ValidationException` if not)
- Wire the new validation into `validate_mock` alongside the existing Map validation
- Create a `MockedStateParallel` class following the `MockedStateMap` pattern to handle mock evaluation for Parallel branches
- Register `MockedStateParallel` in the TestState preprocessor's `_decorate_state_field` function
- Add the `find_state` function to recurse into Parallel state branches (currently only recurses into Map)
- Add test templates (JSON5 state definitions) for Parallel states
- Add parity tests validated against AWS for both validation error cases

## Capabilities

### New Capabilities
- `parallel-mock-validation`: Input validation for Parallel state mock results in the TestState API — ensures mock result is a JSON array with length matching the number of branches.

### Modified Capabilities

## Impact

- `localstack-core/localstack/services/stepfunctions/asl/static_analyser/test_state/test_state_analyser.py` — add Parallel to supported types, add validation method, wire into `validate_mock`
- `localstack-core/localstack/services/stepfunctions/asl/component/test_state/state/` — new `parallel.py` with `MockedStateParallel`
- `localstack-core/localstack/services/stepfunctions/asl/parse/test_state/preprocessor.py` — register Parallel in `_decorate_state_field` and `find_state`
- `tests/aws/services/stepfunctions/templates/test_state/statemachines/` — new Parallel state JSON5 templates
- `tests/aws/services/stepfunctions/templates/test_state/test_state_templates.py` — register new templates
- `tests/aws/services/stepfunctions/v2/test_state/test_state_mock_validation.py` — new parity tests

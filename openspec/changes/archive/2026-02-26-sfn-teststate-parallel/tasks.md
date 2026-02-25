## 1. Test Templates

- [x] 1.1 Create `base_parallel_state.json5` — a minimal Parallel state with 2 branches, each containing a simple Task state (Lambda invoke). Use JSONata query language.
- [x] 1.2 Create `base_parallel_state_3_branches.json5` — a Parallel state with 3 branches for testing branch count mismatch validation.
- [x] 1.3 Register both templates in `TestStateTemplate` class in `test_state_templates.py` as `BASE_PARALLEL_STATE` and `BASE_PARALLEL_STATE_3_BRANCHES`.

## 2. Parity Tests (TDD — validate against AWS first)

- [x] 2.1 Add `test_state_type_requires_mock` parametrization for Parallel state — test that a Parallel state without mock raises `InvalidDefinition`. Add the `BASE_PARALLEL_STATE` template to `STATES_REQUIRING_MOCKS` list. Run against AWS with `AWS_PROFILE=ls-sandbox TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1` to capture snapshot.
- [x] 2.2 Add `test_mock_result_is_not_array_on_parallel_state` test — sends a Parallel state definition with a JSON object as mock result, expects `ValidationException`. Run against AWS to capture snapshot.
- [x] 2.3 Add `test_mock_result_array_size_mismatch_on_parallel_state` test — sends a Parallel state (2 branches) with a 3-element mock result array, expects `ValidationException`. Run against AWS to capture snapshot.

## 3. Static Analyser — Validation Logic

- [x] 3.1 Add `StateType.Parallel` to `_SUPPORTED_STATE_TYPES` in `TestStateStaticAnalyser`.
- [x] 3.2 Add `validate_mock_result_matches_parallel_definition` static method that validates: (a) mock result is a list, and (b) list length equals `len(test_state.branches.programs)`. Use exact AWS error messages from captured snapshots.
- [x] 3.3 Wire the new validation into `validate_mock` — add `isinstance(test_state, StateParallel)` check calling the new method, after the existing Map check.

## 4. MockedStateParallel — Mock Evaluation

- [x] 4.1 Create `parallel.py` in `localstack-core/localstack/services/stepfunctions/asl/component/test_state/state/` with `MockedStateParallel(MockedBaseState[StateParallel])`. Implement `_apply_patches` to wrap `_eval_execution` with `wrap_with_post_return` and wrap each branch program's `_eval_body` with `wrap_with_mock`. Apply `MockedStateExecution.wrap` for Retry/Catch inspection data support.

## 5. Preprocessor Integration

- [x] 5.1 Import `MockedStateParallel` and `StateParallel` in `preprocessor.py`. Add `StateParallel` case to `_decorate_state_field` function calling `MockedStateParallel.wrap`.
- [x] 5.2 Update `find_state` to recurse into `StateParallel` branches — iterate `state.branches.programs` and search each program's `states.states`.

## 6. LocalStack Validation

- [x] 6.1 Run all new and existing TestState parity tests against LocalStack (start with `python -m localstack.dev.run`, verify running, run tests without `TEST_TARGET=AWS_CLOUD`, stop LocalStack, verify stopped). Ensure snapshots match and all tests pass.

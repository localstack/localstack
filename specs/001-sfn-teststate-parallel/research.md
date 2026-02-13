# Research: StepFunctions TestState Parallel State Support

## Decision 1: Validation approach for Parallel mock.result

**Decision**: Follow the exact same validation pattern as Map state, with a
parallel-specific method `validate_mock_result_matches_parallel_definition()`.

**Rationale**: The Map state already has `validate_mock_result_matches_map_definition()`
which checks that mock.result is an array (or object when result_writer is present).
Parallel states always require an array where each element corresponds to a branch.
The existing code in `validate_mock()` already dispatches by `isinstance` check
(`isinstance(test_state, StateMap)`), so adding an `isinstance(test_state, StateParallel)`
check is the natural extension.

**Alternatives considered**:
- Combining Map and Parallel validation into a single generic method: Rejected because
  Map has the `result_writer` special case (object vs array) and Parallel has the
  branch-count check — they are structurally different validations.

## Decision 2: Branch count extraction for size validation

**Decision**: Access `test_state.branches.programs` to get the list of branch programs,
then compare `len(mock_result)` against `len(test_state.branches.programs)`.

**Rationale**: `StateParallel` has a `branches: BranchesDecl` field, and `BranchesDecl`
stores `self.programs: list[Program]`. The length of this list is the number of branches
defined in the Parallel state. This is the most direct and reliable way to get the count.

**Alternatives considered**:
- Parsing the definition JSON again to count branches: Rejected because the ASL parser
  already produces the structured `StateParallel` object with `BranchesDecl`.

## Decision 3: MockedStateParallel class design

**Decision**: Create `MockedStateParallel` as a `MockedBaseState[StateParallel]` subclass,
following the `MockedStateMap` pattern. It wraps the Parallel state to intercept execution
and apply mocked results during TestState evaluation.

**Rationale**: `MockedStateMap` demonstrates the exact pattern: it inherits from
`MockedBaseState`, wraps the state with `MockedStateExecution`, patches internal methods
to inject mocked responses, and handles inspection data. Parallel states have a simpler
execution model (no items_path, no item_selector, no max_concurrency) but need branch-level
mock result injection.

**Key difference from Map**: Map iterates over items sequentially (forced concurrency=1 in
test mode) and injects one mock result per iteration. Parallel has N branches executing
concurrently, and the mock result array provides one result per branch. The `_apply_patches`
method needs to intercept `branches._eval_body` to replace actual branch execution with
mock result injection.

**Alternatives considered**:
- Reusing MockedStateMap directly: Rejected because Parallel has branches (not iterations)
  and lacks Map-specific fields like items_path, item_selector, max_concurrency.

## Decision 4: Preprocessor updates

**Decision**: Update `_decorate_state_field()` in `preprocessor.py` to handle
`StateParallel` by calling `MockedStateParallel.wrap()`. Also update `find_state()`
to recurse into Parallel state branches when looking for nested states.

**Rationale**: The preprocessor is the integration point that connects parsed state
definitions to their test-state mock wrappers. The existing code already handles
`StateMap`, `StateTask`, and common states. Adding `StateParallel` follows the same
pattern.

**Alternatives considered**:
- Handling Parallel decoration elsewhere (e.g., in the provider): Rejected because all
  other state decorations happen in the preprocessor, and moving it would break the pattern.

## Decision 5: Error messages

**Decision**: The exact error messages will be captured by running tests against real AWS
with `TEST_TARGET=AWS_CLOUD SNAPSHOT_UPDATE=1`. Based on the Map state precedent:
- Non-array mock.result: likely `"Mocked result must be an array."` (same as Map)
- Array size mismatch: exact message TBD from AWS snapshot

**Rationale**: Constitution Principle I (AWS Parity First) requires matching AWS behavior
exactly. The Map state error message for non-array is `"Mocked result must be an array."`
via `ValidationException`. The branch-count mismatch message needs to be captured from AWS.

**Alternatives considered**: None — parity testing against real AWS is non-negotiable per
the constitution.

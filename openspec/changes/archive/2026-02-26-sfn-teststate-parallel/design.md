## Context

The StepFunctions TestState API allows testing individual states in isolation with mock configurations. LocalStack already supports mocking for Map states (including mock result validation, branch count checks, and `MockedStateMap` for evaluation). Parallel states share structural similarities with Map — both have sub-programs (branches vs iterations) and produce array results — but Parallel states are currently excluded from TestState support.

The existing code already handles `StateParallel` partially: the `validate_test_state_allows_mocking` method allows Parallel with a mock (same as Map), and `StateParallel` is imported in the analyser. However, `StateType.Parallel` is missing from `_SUPPORTED_STATE_TYPES`, there is no mock result validation, no `MockedStateParallel` class, and the preprocessor doesn't know how to decorate or recurse into Parallel states.

## Goals / Non-Goals

**Goals:**
- Implement two specific input validations for Parallel state mock results:
  1. Mock result must be a valid JSON array
  2. Mock result array length must equal the number of branches in the Parallel state
- Add `MockedStateParallel` to enable mock evaluation for Parallel states during TestState execution
- Register Parallel state in the preprocessor's decoration and state-finding logic
- Achieve AWS parity for these validation behaviors with snapshot-based tests

**Non-Goals:**
- Full Parallel state TestState execution with inspection data (beyond basic mock evaluation) — this can be a follow-up
- Parallel state Retry/Catch mock configuration support (e.g., `stateConfiguration` with retry counts) — follow-up work
- Parallel state without mocks (this already correctly raises `InvalidDefinition` and should continue to do so)

## Decisions

### 1. Validation approach: mirror the Map state pattern

Add `validate_mock_result_matches_parallel_definition` to `TestStateStaticAnalyser`, called from `validate_mock` alongside the existing Map validation. This keeps all static validation co-located and follows the established pattern.

**Alternative**: Validate inside `MockedStateParallel.before_mock()`. Rejected because validation should fail fast before execution begins, and all other structural validations live in the analyser.

### 2. MockedStateParallel: simplified version of MockedStateMap

`MockedStateParallel` will extend `MockedBaseState[StateParallel]` and follow the Map state mocking pattern but simplified:
- Wrap `_eval_execution` with `wrap_with_post_return` for inspection data
- Wrap each branch program's `_eval_body` with `wrap_with_mock` so each branch gets its mock result from the result stack
- The mock result array items are pushed onto the mock result stack in reverse order (LIFO), matching the order branches will pop them

**Alternative**: Reuse `MockedStateMap` directly. Rejected because Parallel states have `BranchesDecl` with `programs` (not `iteration_component`), and the concurrency/items-path semantics don't apply.

### 3. Error messages: match AWS exactly

Validation error messages will be determined by running tests against AWS and capturing the exact error text via snapshots. This ensures parity.

### 4. Test-driven development

Following AGENTS.md, tests will be written first and validated against AWS before implementing the production code. Test templates (JSON5) will define minimal Parallel state definitions with varying branch counts.

## Risks / Trade-offs

- **[Risk] Exact AWS error messages unknown upfront** → Mitigation: TDD approach — run tests against AWS first to capture exact messages in snapshots, then implement to match.
- **[Risk] MockedStateParallel mock result distribution across branches** → Mitigation: Follow the LIFO pattern already used by `TestStateMock._result_stack`. Each branch pops one result. Validate count matches before execution.
- **[Trade-off] Simplified Parallel mock (no Retry/Catch/inspection data parity)** → Acceptable for initial implementation. The two validations are the primary deliverable. Full mocked execution can follow.

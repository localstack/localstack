# Implementation Plan: StepFunctions TestState Parallel State Support

**Branch**: `001-sfn-teststate-parallel` | **Date**: 2026-02-12 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/001-sfn-teststate-parallel/spec.md`

## Summary

Add Parallel state support to the StepFunctions TestState API. This requires:
1. Adding `StateType.Parallel` to the supported state types set in the static analyser
2. Adding mock result validation for Parallel states (must be JSON array, size must match branch count)
3. Creating a `MockedStateParallel` wrapper class following the `MockedStateMap` pattern
4. Updating the preprocessor to decorate Parallel states for TestState execution
5. Adding parity tests validated against real AWS

## Technical Context

**Language/Version**: Python 3.13+
**Primary Dependencies**: LocalStack ASF, ANTLR4 (ASL parser), pytest
**Storage**: In-memory (state stores via `AccountRegionBundle`)
**Testing**: pytest with `@markers.aws.validated` snapshot testing
**Target Platform**: Docker container (Linux)
**Project Type**: Single project (monorepo)
**Performance Goals**: N/A (validation-path feature, no new runtime hot paths)
**Constraints**: Must achieve AWS parity (error codes, messages, response shapes)
**Scale/Scope**: ~5 files modified, ~2 files created, ~1 test file with ~5-8 test cases

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. AWS Parity First | PASS | Error messages will be captured from real AWS via snapshot tests before implementing |
| II. Provider Pattern (ASF) | PASS | No changes to the provider handler; changes are in static analyser and test state wrapper layers which follow existing patterns |
| III. Parity Testing | PASS | All tests will use `@markers.aws.validated` with `snapshot.match()` |
| IV. State Isolation | PASS | No state store changes; Parallel execution already handles multi-branch isolation |
| V. Simplicity and Convention | PASS | Following exact patterns from existing Map state support |
| VI. AGENTS.md Compliance | PASS | Development process follows AGENTS.md: write failing test first, then implement |

No violations. Complexity Tracking not needed.

## Project Structure

### Documentation (this feature)

```text
specs/001-sfn-teststate-parallel/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
└── tasks.md             # Phase 2 output (/speckit.tasks)
```

### Source Code (repository root)

```text
localstack-core/localstack/services/stepfunctions/
├── asl/
│   ├── static_analyser/test_state/
│   │   └── test_state_analyser.py          # MODIFY: add Parallel to supported types,
│   │                                       #   add validate_mock_result_matches_parallel_definition()
│   ├── component/test_state/state/
│   │   └── parallel.py                     # CREATE: MockedStateParallel class
│   └── parse/test_state/
│       └── preprocessor.py                 # MODIFY: add StateParallel decoration in
│                                           #   _decorate_state_field() and find_state()

tests/aws/services/stepfunctions/
├── v2/test_state/
│   └── test_state_mock_validation.py       # MODIFY: add Parallel validation test cases
└── templates/test_state/
    ├── test_state_templates.py             # MODIFY: add BASE_PARALLEL_STATE constant
    └── statemachines/
        └── base_parallel_state.json5       # CREATE: Parallel state template (2 branches)
```

**Structure Decision**: Existing monorepo layout. All changes within the
StepFunctions service directory tree, following the established Map state
pattern.
